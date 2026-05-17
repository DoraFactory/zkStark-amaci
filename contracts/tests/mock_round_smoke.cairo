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
const DEACTIVATE_AFTER_PROCESS: felt252 = 0x210;
const INITIAL_TALLY_COMMITMENT: felt252 = 0;
const FINAL_TALLY_COMMITMENT: felt252 = 0x300;
const KEY_NULLIFIER: felt252 = 0xabc;
const ADD_NEW_KEY_OUTPUT_HASH: felt252 = 0xa01;
const PROCESS_MESSAGES_OUTPUT_HASH: felt252 = 0xa02;
const PROCESS_DEACTIVATE_OUTPUT_HASH: felt252 = 0xa03;
const TALLY_OUTPUT_HASH: felt252 = 0xa04;
const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
const TALLY_VOTES_NATIVE_CIRCUIT_ID: felt252 = 0x414d4143495f54414c4c595f4e4154495645;
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

#[test]
fn mock_round_accepts_native_amaci_flow() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);

    let add_fact = register_fact(
        integrity, round, ADD_NEW_KEY_PROGRAM_HASH, ADD_NEW_KEY_OUTPUT_HASH,
    );
    round
        .submit_add_new_key_fact(KEY_NULLIFIER, STATE_AFTER_KEY, ADD_NEW_KEY_OUTPUT_HASH, add_fact);

    let process_fact = register_fact(
        integrity, round, PROCESS_MESSAGES_PROGRAM_HASH, PROCESS_MESSAGES_OUTPUT_HASH,
    );
    round
        .submit_process_messages_fact(
            STATE_AFTER_KEY,
            STATE_AFTER_MESSAGES,
            INITIAL_DEACTIVATE_COMMITMENT,
            PROCESS_MESSAGES_OUTPUT_HASH,
            process_fact,
        );

    let deactivate_fact = register_fact(
        integrity, round, PROCESS_DEACTIVATE_PROGRAM_HASH, PROCESS_DEACTIVATE_OUTPUT_HASH,
    );
    round
        .submit_process_deactivate_fact(
            INITIAL_DEACTIVATE_COMMITMENT,
            DEACTIVATE_AFTER_PROCESS,
            STATE_AFTER_MESSAGES,
            PROCESS_DEACTIVATE_OUTPUT_HASH,
            deactivate_fact,
        );

    let tally_fact = register_fact(integrity, round, TALLY_PROGRAM_HASH, TALLY_OUTPUT_HASH);
    round
        .submit_tally_fact(
            INITIAL_TALLY_COMMITMENT,
            FINAL_TALLY_COMMITMENT,
            STATE_AFTER_MESSAGES,
            TALLY_OUTPUT_HASH,
            tally_fact,
        );

    assert(round.get_state_commitment() == STATE_AFTER_MESSAGES, 'STATE_NOT_UPDATED');
    assert(round.get_deactivate_commitment() == DEACTIVATE_AFTER_PROCESS, 'DEACT_NOT_UPDATED');
    assert(round.get_tally_commitment() == FINAL_TALLY_COMMITMENT, 'TALLY_NOT_UPDATED');
    assert(round.get_keys_added() == 1, 'KEY_COUNT_BAD');
    assert(round.get_message_batches_processed() == 1, 'MSG_COUNT_BAD');
    assert(round.get_deactivate_batches_processed() == 1, 'DEACT_COUNT_BAD');
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
fn mock_round_accepts_atlantic_metadata_tally_fact() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);
    let metadata_output = array![
        0, 0x99, 1, 14, TALLY_PROGRAM_HASH, 0, 12, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, TALLY_VOTES_NATIVE_CIRCUIT_ID, STARKNET_POSEIDON_HASH_SCHEME,
        2, 1, 1, 0xf00000000, INITIAL_STATE_COMMITMENT, INITIAL_TALLY_COMMITMENT,
        FINAL_TALLY_COMMITMENT, 0x777, 0x88,
    ];
    let fact_hash = round
        .get_expected_bootloaded_fact_hash_for_output(
            SHARP_BOOTLOADER_PROGRAM_HASH, ATLANTIC_METADATA_PROGRAM_HASH, metadata_output.span(),
        );
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    round
        .submit_tally_atlantic_metadata_fact(
            INITIAL_TALLY_COMMITMENT,
            FINAL_TALLY_COMMITMENT,
            INITIAL_STATE_COMMITMENT,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );

    assert(round.get_tally_commitment() == FINAL_TALLY_COMMITMENT, 'TALLY_NOT_UPDATED');
    assert(round.get_total_facts_accepted() == 1, 'FACT_COUNT_BAD');
    assert(round.get_tally_submitted(), 'TALLY_NOT_SUBMITTED');
}

#[test]
fn mock_round_accepts_configured_integrity_verification_hash() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, VERIFIER_CONFIG_HASH);

    let fact_hash = round.get_expected_fact_hash(ADD_NEW_KEY_PROGRAM_HASH, ADD_NEW_KEY_OUTPUT_HASH);
    let verification_hash = round.get_expected_verification_hash(fact_hash);
    integrity.set_verification_hash_valid(verification_hash, true);

    round
        .submit_add_new_key_fact(
            KEY_NULLIFIER, STATE_AFTER_KEY, ADD_NEW_KEY_OUTPUT_HASH, fact_hash,
        );

    assert(round.get_state_commitment() == STATE_AFTER_KEY, 'STATE_NOT_UPDATED');
    assert(round.get_total_facts_accepted() == 1, 'FACT_COUNT_BAD');
}

#[test]
#[should_panic]
fn mock_round_rejects_unregistered_fact() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);

    let fact_hash = round.get_expected_fact_hash(ADD_NEW_KEY_PROGRAM_HASH, ADD_NEW_KEY_OUTPUT_HASH);
    round
        .submit_add_new_key_fact(
            KEY_NULLIFIER, STATE_AFTER_KEY, ADD_NEW_KEY_OUTPUT_HASH, fact_hash,
        );
}

#[test]
#[should_panic]
fn mock_round_rejects_duplicate_key_nullifier() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);

    let fact_hash = register_fact(
        integrity, round, ADD_NEW_KEY_PROGRAM_HASH, ADD_NEW_KEY_OUTPUT_HASH,
    );
    round
        .submit_add_new_key_fact(
            KEY_NULLIFIER, STATE_AFTER_KEY, ADD_NEW_KEY_OUTPUT_HASH, fact_hash,
        );
    round
        .submit_add_new_key_fact(
            KEY_NULLIFIER, STATE_AFTER_KEY + 1, ADD_NEW_KEY_OUTPUT_HASH, fact_hash,
        );
}

#[test]
#[should_panic]
fn mock_round_rejects_stale_process_messages_state() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);

    let fact_hash = register_fact(
        integrity, round, PROCESS_MESSAGES_PROGRAM_HASH, PROCESS_MESSAGES_OUTPUT_HASH,
    );
    round
        .submit_process_messages_fact(
            STATE_AFTER_KEY,
            STATE_AFTER_MESSAGES,
            INITIAL_DEACTIVATE_COMMITMENT,
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
    let fact_hash = round.get_expected_fact_hash(disallowed_program_hash, ADD_NEW_KEY_OUTPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    round.submit_operation_fact(0x99, disallowed_program_hash, ADD_NEW_KEY_OUTPUT_HASH, fact_hash);
}

#[test]
#[should_panic]
fn mock_round_rejects_second_tally_submission() {
    let integrity = deploy_mock_integrity();
    let round = deploy_round(integrity.contract_address, 0);

    let fact_hash = register_fact(integrity, round, TALLY_PROGRAM_HASH, TALLY_OUTPUT_HASH);
    round
        .submit_tally_fact(
            INITIAL_TALLY_COMMITMENT,
            FINAL_TALLY_COMMITMENT,
            INITIAL_STATE_COMMITMENT,
            TALLY_OUTPUT_HASH,
            fact_hash,
        );
    round
        .submit_tally_fact(
            FINAL_TALLY_COMMITMENT,
            FINAL_TALLY_COMMITMENT + 1,
            INITIAL_STATE_COMMITMENT,
            TALLY_OUTPUT_HASH,
            fact_hash,
        );
}
