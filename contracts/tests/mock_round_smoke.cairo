use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use zkstark_amaci_contracts::integrity_fact_registry::FACT_REGISTRY_MODE_DIRECT;
use zkstark_amaci_contracts::mock_amaci_round::{
    IMockAmaciRoundDispatcher, IMockAmaciRoundDispatcherTrait,
};
use zkstark_amaci_contracts::mock_integrity::{
    IMockIntegrityDispatcher, IMockIntegrityDispatcherTrait,
};

const ADMIN: felt252 = 0x42;
const ADD_NEW_KEY_PROGRAM_HASH: felt252 = 0x1111;
const PROCESS_MESSAGES_PROGRAM_HASH: felt252 = 0x2222;
const PROCESS_DEACTIVATE_PROGRAM_HASH: felt252 = 0x3333;
const TALLY_PROGRAM_HASH: felt252 = 0x4444;
const ATLANTIC_METADATA_PROGRAM_HASH: felt252 = 0x5555;
const SHARP_BOOTLOADER_PROGRAM_HASH: felt252 =
    0x5ab580b04e3532b6b18f81cfa654a05e29dd8e2352d88df1e765a84072db07;
const VERIFIER_CONFIG_HASH: felt252 = 0x9abc;
const MIN_SECURITY_BITS: u32 = 80;
const INITIAL_STATE_COMMITMENT: felt252 = 0x100;
const STATE_AFTER_KEY: felt252 = 0x110;
const STATE_AFTER_MESSAGES: felt252 = 0x120;
const INITIAL_DEACTIVATE_COMMITMENT: felt252 = 0x200;
const DEACTIVATE_ROOT_AFTER_PROCESS: felt252 = 0x205;
const DEACTIVATE_AFTER_PROCESS: felt252 = 0x210;
const INITIAL_TALLY_COMMITMENT: felt252 = 0;
const FINAL_TALLY_COMMITMENT: felt252 = 0x300;
const KEY_NULLIFIER: felt252 = 0xabc;
const PROCESS_MESSAGES_OUTPUT_HASH: felt252 = 0xa02;
const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
const TALLY_VOTES_NATIVE_CIRCUIT_ID: felt252 = 0x414d4143495f54414c4c595f4e4154495645;
const ADD_NEW_KEY_NATIVE_CIRCUIT_ID: felt252 = 0x414d4143495f4144445f4b45595f4e4154495645;
const PROCESS_MESSAGES_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f4d53475f4e4154495645;
const PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID: felt252 =
    0x414d4143495f50524f434553535f44454143545f4e4154495645;
const STARKNET_POSEIDON_HASH_SCHEME: felt252 = 0x535441524b4e45545f504f534549444f4e;

fn deploy_mock_integrity() -> IMockIntegrityDispatcher {
    let contract = declare("MockIntegrity").unwrap().contract_class();
    let calldata = array![];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    IMockIntegrityDispatcher { contract_address }
}

fn deploy_round(
    integrity: ContractAddress, verifier_config_hash: felt252,
) -> IMockAmaciRoundDispatcher {
    let contract = declare("MockAmaciRound").unwrap().contract_class();
    let calldata = array![
        ADMIN, integrity.into(), FACT_REGISTRY_MODE_DIRECT, false.into(), verifier_config_hash,
        MIN_SECURITY_BITS.into(), ADD_NEW_KEY_PROGRAM_HASH, PROCESS_MESSAGES_PROGRAM_HASH,
        PROCESS_DEACTIVATE_PROGRAM_HASH, TALLY_PROGRAM_HASH, INITIAL_STATE_COMMITMENT,
        INITIAL_DEACTIVATE_COMMITMENT, INITIAL_TALLY_COMMITMENT,
    ];

    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    IMockAmaciRoundDispatcher { contract_address }
}

fn register_fact(
    integrity: IMockIntegrityDispatcher,
    round: IMockAmaciRoundDispatcher,
    program_hash: felt252,
    public_output_hash: felt252,
) -> felt252 {
    let fact_hash = round.get_expected_fact_hash(program_hash, public_output_hash);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);
    fact_hash
}

fn register_metadata_fact(
    integrity: IMockIntegrityDispatcher,
    round: IMockAmaciRoundDispatcher,
    metadata_output: Span<felt252>,
) -> felt252 {
    let fact_hash = round
        .get_expected_bootloaded_fact_hash_for_output(
            SHARP_BOOTLOADER_PROGRAM_HASH, ATLANTIC_METADATA_PROGRAM_HASH, metadata_output,
        );
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);
    fact_hash
}

fn register_metadata_verification_fact(
    integrity: IMockIntegrityDispatcher,
    round: IMockAmaciRoundDispatcher,
    metadata_output: Span<felt252>,
) -> felt252 {
    let fact_hash = round
        .get_expected_bootloaded_fact_hash_for_output(
            SHARP_BOOTLOADER_PROGRAM_HASH, ATLANTIC_METADATA_PROGRAM_HASH, metadata_output,
        );
    let verification_hash = round.get_expected_verification_hash(fact_hash);
    integrity.set_verification_hash_valid(verification_hash, true);
    fact_hash
}

fn vote_message() -> Array<felt252> {
    array![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
}

fn deactivate_message() -> Array<felt252> {
    array![11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
}

fn process_deactivate_metadata(round: IMockAmaciRoundDispatcher) -> Array<felt252> {
    array![
        0, 0x99, 1, 18, PROCESS_DEACTIVATE_PROGRAM_HASH, 0, 16, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID,
        STARKNET_POSEIDON_HASH_SCHEME, 2, 4, 3, DEACTIVATE_ROOT_AFTER_PROCESS, 0x402,
        round.get_deactivate_message_hash(0), round.get_deactivate_message_hash(1),
        INITIAL_DEACTIVATE_COMMITMENT, DEACTIVATE_AFTER_PROCESS, 0x405, 0x406, 0x407,
    ]
}

fn add_new_key_metadata(deactivate_root: felt252) -> Array<felt252> {
    array![
        0, 0x99, 1, 21, ADD_NEW_KEY_PROGRAM_HASH, 0, 19, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, ADD_NEW_KEY_NATIVE_CIRCUIT_ID, STARKNET_POSEIDON_HASH_SCHEME,
        2, 4, deactivate_root, 0x202, KEY_NULLIFIER, 0x203, 0x204, 0x205, 0x206, 0x207, 0x208,
        0x209, 0x20a, 0x20b, 0x20c,
    ]
}

fn process_messages_metadata(round: IMockAmaciRoundDispatcher) -> Array<felt252> {
    array![
        0, 0x99, 1, 18, PROCESS_MESSAGES_PROGRAM_HASH, 0, 16, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
        STARKNET_POSEIDON_HASH_SCHEME, 2, 1, 3, 0x301, 0x302, round.get_message_hash(0),
        round.get_message_hash(1), STATE_AFTER_KEY, STATE_AFTER_MESSAGES, DEACTIVATE_AFTER_PROCESS,
        0x305, 0x306,
    ]
}

fn tally_metadata() -> Array<felt252> {
    array![
        0, 0x99, 1, 14, TALLY_PROGRAM_HASH, 0, 12, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, TALLY_VOTES_NATIVE_CIRCUIT_ID, STARKNET_POSEIDON_HASH_SCHEME,
        2, 1, 1, 0xf00000000, STATE_AFTER_MESSAGES, INITIAL_TALLY_COMMITMENT,
        FINAL_TALLY_COMMITMENT, 0x777, 0x88,
    ]
}

fn sign_up_and_publish_deactivate(round: IMockAmaciRoundDispatcher) {
    round.sign_up(0x701, 0x702, 77);
    let dmsg = deactivate_message();
    round.publish_deactivate_message(dmsg.span(), 0x901, 0x902);
}

fn process_deactivate(integrity: IMockIntegrityDispatcher, round: IMockAmaciRoundDispatcher) {
    let metadata_output = process_deactivate_metadata(round);
    let fact_hash = register_metadata_fact(integrity, round, metadata_output.span());
    submit_process_deactivate(round, metadata_output, fact_hash);
}

fn process_deactivate_with_verification_hash(
    integrity: IMockIntegrityDispatcher, round: IMockAmaciRoundDispatcher,
) {
    let metadata_output = process_deactivate_metadata(round);
    let fact_hash = register_metadata_verification_fact(integrity, round, metadata_output.span());
    submit_process_deactivate(round, metadata_output, fact_hash);
}

fn submit_process_deactivate(
    round: IMockAmaciRoundDispatcher, metadata_output: Array<felt252>, fact_hash: felt252,
) {
    round
        .submit_process_deactivate_atlantic_metadata_fact(
            INITIAL_DEACTIVATE_COMMITMENT,
            DEACTIVATE_AFTER_PROCESS,
            INITIAL_STATE_COMMITMENT,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );
}

fn add_new_key(integrity: IMockIntegrityDispatcher, round: IMockAmaciRoundDispatcher) {
    let metadata_output = add_new_key_metadata(round.get_deactivate_root());
    let fact_hash = register_metadata_fact(integrity, round, metadata_output.span());
    round
        .submit_add_new_key_atlantic_metadata_fact(
            KEY_NULLIFIER,
            STATE_AFTER_KEY,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );
}

fn publish_vote_and_process_messages(
    integrity: IMockIntegrityDispatcher, round: IMockAmaciRoundDispatcher,
) {
    let msg = vote_message();
    round.publish_message(msg.span(), 0x801, 0x802);
    let metadata_output = process_messages_metadata(round);
    let fact_hash = register_metadata_fact(integrity, round, metadata_output.span());
    round
        .submit_process_messages_atlantic_metadata_fact(
            STATE_AFTER_KEY,
            STATE_AFTER_MESSAGES,
            DEACTIVATE_AFTER_PROCESS,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );
}

fn submit_tally(integrity: IMockIntegrityDispatcher, round: IMockAmaciRoundDispatcher) {
    let metadata_output = tally_metadata();
    let fact_hash = register_metadata_fact(integrity, round, metadata_output.span());
    round
        .submit_tally_atlantic_metadata_fact(
            INITIAL_TALLY_COMMITMENT,
            FINAL_TALLY_COMMITMENT,
            STATE_AFTER_MESSAGES,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );
}

#[test]
fn mock_round_accepts_standard_amaci_flow() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);

    sign_up_and_publish_deactivate(round);
    process_deactivate(integrity, round);
    add_new_key(integrity, round);
    publish_vote_and_process_messages(integrity, round);
    submit_tally(integrity, round);

    assert(round.get_num_signups() == 1, 'SIGNUPS_BAD');
    assert(round.get_deactivate_message_chain_length() == 1, 'DMSG_LEN_BAD');
    assert(round.get_processed_deactivate_message_count() == 1, 'DMSG_COUNT_BAD');
    assert(round.get_deactivate_root() == DEACTIVATE_ROOT_AFTER_PROCESS, 'DEACT_ROOT_BAD');
    assert(round.get_state_commitment() == STATE_AFTER_MESSAGES, 'STATE_NOT_UPDATED');
    assert(round.get_deactivate_commitment() == DEACTIVATE_AFTER_PROCESS, 'DEACT_NOT_UPDATED');
    assert(round.get_message_chain_length() == 1, 'MSG_LEN_BAD');
    assert(round.get_processed_message_count() == 1, 'MSG_COUNT_BAD');
    assert(round.get_tally_commitment() == FINAL_TALLY_COMMITMENT, 'TALLY_NOT_UPDATED');
    assert(round.get_keys_added() == 1, 'KEY_COUNT_BAD');
    assert(round.get_message_batches_processed() == 1, 'MSG_BATCH_COUNT_BAD');
    assert(round.get_deactivate_batches_processed() == 1, 'DEACT_BATCH_COUNT_BAD');
    assert(round.get_total_facts_accepted() == 4, 'FACT_COUNT_BAD');
    assert(round.get_tally_submitted(), 'TALLY_NOT_SUBMITTED');
}

#[test]
fn mock_round_accepts_generic_split_component_fact() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);

    let fact_hash = register_fact(
        integrity, round, PROCESS_MESSAGES_PROGRAM_HASH, PROCESS_MESSAGES_OUTPUT_HASH,
    );

    round
        .submit_operation_fact(
            0x50524f434553535f4d5347,
            PROCESS_MESSAGES_PROGRAM_HASH,
            PROCESS_MESSAGES_OUTPUT_HASH,
            fact_hash,
        );

    assert(round.get_total_facts_accepted() == 1, 'FACT_COUNT_BAD');
}

#[test]
fn mock_round_accepts_configured_integrity_verification_hash() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, VERIFIER_CONFIG_HASH);
    sign_up_and_publish_deactivate(round);
    process_deactivate_with_verification_hash(integrity, round);

    let metadata_output = add_new_key_metadata(round.get_deactivate_root());
    let fact_hash = register_metadata_verification_fact(integrity, round, metadata_output.span());

    round
        .submit_add_new_key_atlantic_metadata_fact(
            KEY_NULLIFIER,
            STATE_AFTER_KEY,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );

    assert(round.get_state_commitment() == STATE_AFTER_KEY, 'STATE_NOT_UPDATED');
    assert(round.get_total_facts_accepted() == 2, 'FACT_COUNT_BAD');
}

#[test]
#[should_panic]
fn mock_round_rejects_add_new_key_before_deactivate() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);
    round.sign_up(0x701, 0x702, 77);
    let metadata_output = add_new_key_metadata(DEACTIVATE_ROOT_AFTER_PROCESS);
    let fact_hash = register_metadata_fact(integrity, round, metadata_output.span());

    round
        .submit_add_new_key_atlantic_metadata_fact(
            KEY_NULLIFIER,
            STATE_AFTER_KEY,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );
}

#[test]
#[should_panic]
fn mock_round_rejects_process_deactivate_without_message() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);
    round.sign_up(0x701, 0x702, 77);
    let metadata_output = process_deactivate_metadata(round);
    let fact_hash = register_metadata_fact(integrity, round, metadata_output.span());

    round
        .submit_process_deactivate_atlantic_metadata_fact(
            INITIAL_DEACTIVATE_COMMITMENT,
            DEACTIVATE_AFTER_PROCESS,
            INITIAL_STATE_COMMITMENT,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );
}

#[test]
#[should_panic]
fn mock_round_rejects_add_new_key_with_wrong_deactivate_root() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);
    sign_up_and_publish_deactivate(round);
    process_deactivate(integrity, round);

    let metadata_output = add_new_key_metadata(DEACTIVATE_ROOT_AFTER_PROCESS + 1);
    let fact_hash = register_metadata_fact(integrity, round, metadata_output.span());
    round
        .submit_add_new_key_atlantic_metadata_fact(
            KEY_NULLIFIER,
            STATE_AFTER_KEY,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );
}

#[test]
#[should_panic]
fn mock_round_rejects_process_messages_before_vote_message() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);
    sign_up_and_publish_deactivate(round);
    process_deactivate(integrity, round);
    add_new_key(integrity, round);
    let metadata_output = process_messages_metadata(round);
    let fact_hash = register_metadata_fact(integrity, round, metadata_output.span());

    round
        .submit_process_messages_atlantic_metadata_fact(
            STATE_AFTER_KEY,
            STATE_AFTER_MESSAGES,
            DEACTIVATE_AFTER_PROCESS,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );
}

#[test]
#[should_panic]
fn mock_round_rejects_unregistered_fact() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);
    sign_up_and_publish_deactivate(round);
    process_deactivate(integrity, round);

    let metadata_output = add_new_key_metadata(round.get_deactivate_root());
    let fact_hash = round
        .get_expected_bootloaded_fact_hash_for_output(
            SHARP_BOOTLOADER_PROGRAM_HASH, ATLANTIC_METADATA_PROGRAM_HASH, metadata_output.span(),
        );
    round
        .submit_add_new_key_atlantic_metadata_fact(
            KEY_NULLIFIER,
            STATE_AFTER_KEY,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );
}

#[test]
#[should_panic]
fn mock_round_rejects_duplicate_key_nullifier() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);
    sign_up_and_publish_deactivate(round);
    process_deactivate(integrity, round);
    add_new_key(integrity, round);
    add_new_key(integrity, round);
}

#[test]
#[should_panic]
fn mock_round_rejects_stale_process_messages_state() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);
    sign_up_and_publish_deactivate(round);
    process_deactivate(integrity, round);
    add_new_key(integrity, round);

    let msg = vote_message();
    round.publish_message(msg.span(), 0x801, 0x802);
    let fact_hash = register_fact(
        integrity, round, PROCESS_MESSAGES_PROGRAM_HASH, PROCESS_MESSAGES_OUTPUT_HASH,
    );
    round
        .submit_process_messages_fact(
            INITIAL_STATE_COMMITMENT,
            STATE_AFTER_MESSAGES,
            DEACTIVATE_AFTER_PROCESS,
            PROCESS_MESSAGES_OUTPUT_HASH,
            fact_hash,
        );
}

#[test]
#[should_panic]
fn mock_round_rejects_disallowed_program_hash() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);

    let disallowed_program_hash = 0x9999;
    let fact_hash = round
        .get_expected_fact_hash(disallowed_program_hash, PROCESS_MESSAGES_OUTPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    round
        .submit_operation_fact(
            0x99, disallowed_program_hash, PROCESS_MESSAGES_OUTPUT_HASH, fact_hash,
        );
}

#[test]
#[should_panic]
fn mock_round_rejects_second_tally_submission() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);
    sign_up_and_publish_deactivate(round);
    process_deactivate(integrity, round);
    add_new_key(integrity, round);
    publish_vote_and_process_messages(integrity, round);
    submit_tally(integrity, round);

    round
        .submit_tally_fact(
            FINAL_TALLY_COMMITMENT, FINAL_TALLY_COMMITMENT + 1, STATE_AFTER_MESSAGES, 0xa04, 0xa04,
        );
}
