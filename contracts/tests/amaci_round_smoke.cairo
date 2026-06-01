use core::hash::HashStateTrait;
use core::poseidon::PoseidonTrait;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address,
};
use starknet::ContractAddress;
use zkstark_amaci_contracts::amaci_round::{IAmaciRoundDispatcher, IAmaciRoundDispatcherTrait};
use zkstark_amaci_contracts::integrity_fact_registry::FACT_REGISTRY_MODE_DIRECT;
use zkstark_amaci_contracts::mock_integrity::{
    IMockIntegrityDispatcher, IMockIntegrityDispatcherTrait,
};

const ADMIN: felt252 = 0x42;
const OPERATOR: felt252 = 0x43;
const FEE_RECIPIENT: felt252 = 0x44;
const USER_1: felt252 = 0x101;
const ADD_NEW_KEY_PROGRAM_HASH: felt252 = 0x1111;
const PROCESS_MESSAGES_PROGRAM_HASH: felt252 = 0x2222;
const PROCESS_DEACTIVATE_PROGRAM_HASH: felt252 = 0x3333;
const TALLY_PROGRAM_HASH: felt252 = 0x4444;
const ATLANTIC_METADATA_PROGRAM_HASH: felt252 = 0x5555;
const SHARP_BOOTLOADER_PROGRAM_HASH: felt252 =
    0x5ab580b04e3532b6b18f81cfa654a05e29dd8e2352d88df1e765a84072db07;
const MIN_SECURITY_BITS: u32 = 80;
const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
const TALLY_VOTES_NATIVE_CIRCUIT_ID: felt252 = 0x414d4143495f54414c4c595f4e4154495645;
const ADD_NEW_KEY_NATIVE_CIRCUIT_ID: felt252 = 0x414d4143495f4144445f4b45595f4e4154495645;
const PROCESS_MESSAGES_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f4d53475f4e4154495645;
const PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f44454143545f4e4154495645;
const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;
const PERIOD_PENDING: felt252 = 0;
const PERIOD_PROCESSING: felt252 = 1;
const PERIOD_TALLYING: felt252 = 2;
const PERIOD_ENDED: felt252 = 3;
const REGISTRATION_STATIC_WHITELIST: felt252 = 0;
const VOICE_CREDIT_DYNAMIC: felt252 = 1;
const COORDINATOR_PUB_KEY_HASH: felt252 = 0xc001;
const STATE_SALT: felt252 = 0xabc1;
const INITIAL_DEACTIVATE_ROOT: felt252 = 0xd001;
const INITIAL_DEACTIVATE_COMMITMENT: felt252 = 0xd002;
const NEW_DEACTIVATE_ROOT: felt252 = 0xd003;
const NEW_DEACTIVATE_COMMITMENT: felt252 = 0xd004;
const NEW_STATE_COMMITMENT: felt252 = 0xaabb;
const FINAL_TALLY_COMMITMENT_SALT: felt252 = 0x777;
const POLL_ID: felt252 = 0x2113;
const TWO_POW_32: felt252 = 0x100000000;
const KEY_NULLIFIER: felt252 = 0x5151;

fn admin_address() -> ContractAddress {
    ADMIN.try_into().unwrap()
}

fn operator_address() -> ContractAddress {
    OPERATOR.try_into().unwrap()
}

fn user_1_address() -> ContractAddress {
    USER_1.try_into().unwrap()
}

fn deploy_mock_integrity() -> IMockIntegrityDispatcher {
    let contract = declare("MockIntegrity").unwrap().contract_class();
    let calldata = array![];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    IMockIntegrityDispatcher { contract_address }
}

fn deploy_round(integrity: ContractAddress) -> IAmaciRoundDispatcher {
    let contract = declare("AmaciRound").unwrap().contract_class();
    let calldata = array![
        ADMIN, OPERATOR, FEE_RECIPIENT, integrity.into(), FACT_REGISTRY_MODE_DIRECT, false.into(),
        0, MIN_SECURITY_BITS.into(), ADD_NEW_KEY_PROGRAM_HASH, PROCESS_MESSAGES_PROGRAM_HASH,
        PROCESS_DEACTIVATE_PROGRAM_HASH, TALLY_PROGRAM_HASH, POLL_ID, COORDINATOR_PUB_KEY_HASH,
        STATE_SALT, INITIAL_DEACTIVATE_ROOT, INITIAL_DEACTIVATE_COMMITMENT,
        REGISTRATION_STATIC_WHITELIST, VOICE_CREDIT_DYNAMIC, 0, 100, true.into(), 10, 100, 0, 3, 11,
        22, 33,
    ];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    IAmaciRoundDispatcher { contract_address }
}

fn register_fact(
    integrity: IMockIntegrityDispatcher,
    round: IAmaciRoundDispatcher,
    metadata_output: Span<felt252>,
) -> felt252 {
    let fact_hash = round
        .get_expected_bootloaded_fact_hash_for_output(
            SHARP_BOOTLOADER_PROGRAM_HASH, ATLANTIC_METADATA_PROGRAM_HASH, metadata_output,
        );
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);
    fact_hash
}

fn hash_pair(left: felt252, right: felt252) -> felt252 {
    PoseidonTrait::new().update(left).update(right).finalize()
}

fn hash5(v0: felt252, v1: felt252, v2: felt252, v3: felt252, v4: felt252) -> felt252 {
    PoseidonTrait::new().update(v0).update(v1).update(v2).update(v3).update(v4).finalize()
}

fn results_commitment(r0: felt252, r1: felt252, r2: felt252, salt: felt252) -> felt252 {
    hash_pair(hash5(r0, r1, r2, 0, 0), salt)
}

fn message() -> Array<felt252> {
    array![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
}

fn deactivate_message() -> Array<felt252> {
    array![21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
}

fn process_deactivate_metadata(round: IAmaciRoundDispatcher) -> Array<felt252> {
    array![
        0, 0x99, 1, 18, PROCESS_DEACTIVATE_PROGRAM_HASH, 0, 16, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID,
        STARKNET_POSEIDON_HASH_SCHEME, 2, 4, 3, NEW_DEACTIVATE_ROOT, COORDINATOR_PUB_KEY_HASH,
        round.get_deactivate_message_hash(0), round.get_deactivate_message_hash(1),
        INITIAL_DEACTIVATE_COMMITMENT, NEW_DEACTIVATE_COMMITMENT, round.get_state_root(), POLL_ID,
        0xbeef,
    ]
}

fn add_new_key_metadata(round: IAmaciRoundDispatcher, new_pub_key_hash: felt252) -> Array<felt252> {
    array![
        0, 0x99, 1, 21, ADD_NEW_KEY_PROGRAM_HASH, 0, 19, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, ADD_NEW_KEY_NATIVE_CIRCUIT_ID, STARKNET_POSEIDON_HASH_SCHEME,
        2, 4, round.get_deactivate_root(), COORDINATOR_PUB_KEY_HASH, KEY_NULLIFIER, 0x301, 0x302,
        0x303, 0x304, 0x305, 0x306, 0x307, new_pub_key_hash, POLL_ID, 0x308,
    ]
}

fn process_messages_metadata(
    round: IAmaciRoundDispatcher, new_state_commitment: felt252,
) -> Array<felt252> {
    array![
        0, 0x99, 1, 18, PROCESS_MESSAGES_PROGRAM_HASH, 0, 16, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
        STARKNET_POSEIDON_HASH_SCHEME, 2, 1, 3,
        round.get_num_signups().into() * TWO_POW_32 + round.get_vote_options_len().into(),
        COORDINATOR_PUB_KEY_HASH, round.get_message_hash(0), round.get_message_hash(1),
        round.get_state_commitment(), new_state_commitment, NEW_DEACTIVATE_COMMITMENT, POLL_ID,
        0xcafe,
    ]
}

fn tally_metadata(round: IAmaciRoundDispatcher, new_tally_commitment: felt252) -> Array<felt252> {
    array![
        0, 0x99, 1, 14, TALLY_PROGRAM_HASH, 0, 12, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, TALLY_VOTES_NATIVE_CIRCUIT_ID, STARKNET_POSEIDON_HASH_SCHEME,
        2, 1, 1, round.get_num_signups().into() * TWO_POW_32, round.get_state_commitment(),
        round.get_tally_commitment(), new_tally_commitment, 0xd00d,
    ]
}

fn setup_registered_round() -> (IMockIntegrityDispatcher, IAmaciRoundDispatcher) {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address);
    start_cheat_caller_address(round.contract_address, admin_address());
    round.set_static_whitelist_user(user_1_address(), 77, true);
    start_cheat_block_timestamp(round.contract_address, 20);
    start_cheat_caller_address(round.contract_address, user_1_address());
    round.sign_up(0x701, 0x702, 0);
    (integrity, round)
}

#[test]
fn amaci_round_accepts_static_whitelist_full_round() {
    let (integrity, round) = setup_registered_round();
    assert(round.get_period() == PERIOD_PENDING, 'PERIOD_NOT_PENDING');
    assert(round.get_num_signups() == 1, 'SIGNUPS_BAD');

    start_cheat_caller_address(round.contract_address, user_1_address());
    let msg = message();
    round.publish_message(msg.span(), 0x801, 0x802);
    let dmsg = deactivate_message();
    round.publish_deactivate_message(dmsg.span(), 0x901, 0x902);
    assert(round.get_message_chain_length() == 1, 'MSG_LEN_BAD');
    assert(round.get_deactivate_message_chain_length() == 1, 'DMSG_LEN_BAD');

    start_cheat_caller_address(round.contract_address, operator_address());
    let deactivate_output = process_deactivate_metadata(round);
    let deactivate_fact = register_fact(integrity, round, deactivate_output.span());
    round
        .submit_process_deactivate_atlantic_metadata_fact(
            INITIAL_DEACTIVATE_COMMITMENT,
            NEW_DEACTIVATE_COMMITMENT,
            ATLANTIC_METADATA_PROGRAM_HASH,
            deactivate_output.span(),
            deactivate_fact,
        );
    assert(round.get_processed_deactivate_message_count() == 1, 'DMSG_COUNT_BAD');
    assert(round.get_deactivate_commitment() == NEW_DEACTIVATE_COMMITMENT, 'DEACT_BAD');

    start_cheat_block_timestamp(round.contract_address, 100);
    round.start_process_period();
    assert(round.get_period() == PERIOD_PROCESSING, 'NOT_PROCESSING');

    let process_output = process_messages_metadata(round, NEW_STATE_COMMITMENT);
    let process_fact = register_fact(integrity, round, process_output.span());
    round
        .submit_process_messages_atlantic_metadata_fact(
            round.get_state_commitment(),
            NEW_STATE_COMMITMENT,
            NEW_DEACTIVATE_COMMITMENT,
            ATLANTIC_METADATA_PROGRAM_HASH,
            process_output.span(),
            process_fact,
        );
    assert(round.get_processed_message_count() == 1, 'MSG_COUNT_BAD');
    assert(round.get_state_commitment() == NEW_STATE_COMMITMENT, 'STATE_BAD');

    round.stop_processing_period();
    assert(round.get_period() == PERIOD_TALLYING, 'NOT_TALLYING');

    let final_tally = results_commitment(5, 3, 1, FINAL_TALLY_COMMITMENT_SALT);
    let tally_output = tally_metadata(round, final_tally);
    let tally_fact = register_fact(integrity, round, tally_output.span());
    round
        .submit_tally_atlantic_metadata_fact(
            0, final_tally, ATLANTIC_METADATA_PROGRAM_HASH, tally_output.span(), tally_fact,
        );
    assert(round.get_processed_user_count() == 1, 'USER_COUNT_BAD');
    assert(round.get_tally_commitment() == final_tally, 'TALLY_BAD');

    round.stop_tallying_period(array![5, 3, 1].span(), FINAL_TALLY_COMMITMENT_SALT);
    assert(round.get_period() == PERIOD_ENDED, 'NOT_ENDED');
    assert(round.get_result(0) == 5, 'RESULT_0_BAD');
    assert(round.get_total_result() == 9, 'TOTAL_BAD');
    assert(round.get_total_facts_accepted() == 3, 'FACT_COUNT_BAD');
}

#[test]
fn amaci_round_accepts_add_new_key_native_fact() {
    let (integrity, round) = setup_registered_round();
    start_cheat_caller_address(round.contract_address, operator_address());
    let new_pub_key_hash = hash_pair(0x711, 0x712);
    let output = add_new_key_metadata(round, new_pub_key_hash);
    let fact = register_fact(integrity, round, output.span());

    round
        .submit_add_new_key_atlantic_metadata_fact(
            0x711, 0x712, KEY_NULLIFIER, ATLANTIC_METADATA_PROGRAM_HASH, output.span(), fact,
        );

    assert(round.get_num_signups() == 2, 'SIGNUPS_BAD');
    assert(round.is_key_nullifier_used(KEY_NULLIFIER), 'NULLIFIER_NOT_USED');
    assert(round.is_registered_pub_key(new_pub_key_hash), 'KEY_NOT_REGISTERED');
    assert(round.get_total_facts_accepted() == 1, 'FACT_COUNT_BAD');
}

#[test]
#[should_panic]
fn amaci_round_rejects_unregistered_integrity_fact() {
    let (_integrity, round) = setup_registered_round();
    start_cheat_caller_address(round.contract_address, user_1_address());
    let dmsg = deactivate_message();
    round.publish_deactivate_message(dmsg.span(), 0x901, 0x902);
    start_cheat_caller_address(round.contract_address, operator_address());
    let deactivate_output = process_deactivate_metadata(round);
    let fake_fact = round
        .get_expected_bootloaded_fact_hash_for_output(
            SHARP_BOOTLOADER_PROGRAM_HASH, ATLANTIC_METADATA_PROGRAM_HASH, deactivate_output.span(),
        );
    round
        .submit_process_deactivate_atlantic_metadata_fact(
            INITIAL_DEACTIVATE_COMMITMENT,
            NEW_DEACTIVATE_COMMITMENT,
            ATLANTIC_METADATA_PROGRAM_HASH,
            deactivate_output.span(),
            fake_fact,
        );
}

#[test]
#[should_panic]
fn amaci_round_rejects_process_message_with_wrong_chain_hash() {
    let (integrity, round) = setup_registered_round();
    start_cheat_caller_address(round.contract_address, user_1_address());
    let msg = message();
    round.publish_message(msg.span(), 0x801, 0x802);
    start_cheat_block_timestamp(round.contract_address, 100);
    start_cheat_caller_address(round.contract_address, operator_address());
    round.start_process_period();

    let bad_output = array![
        0, 0x99, 1, 18, PROCESS_MESSAGES_PROGRAM_HASH, 0, 16, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
        STARKNET_POSEIDON_HASH_SCHEME, 2, 1, 3,
        round.get_num_signups().into() * TWO_POW_32 + round.get_vote_options_len().into(),
        COORDINATOR_PUB_KEY_HASH, 0xdead, round.get_message_hash(1), round.get_state_commitment(),
        NEW_STATE_COMMITMENT, INITIAL_DEACTIVATE_COMMITMENT, POLL_ID, 0xcafe,
    ];
    let fact = register_fact(integrity, round, bad_output.span());
    round
        .submit_process_messages_atlantic_metadata_fact(
            round.get_state_commitment(),
            NEW_STATE_COMMITMENT,
            INITIAL_DEACTIVATE_COMMITMENT,
            ATLANTIC_METADATA_PROGRAM_HASH,
            bad_output.span(),
            fact,
        );
}
