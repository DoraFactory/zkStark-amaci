use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use zkstark_amaci_contracts::add_new_key_wrapper::{
    IAddNewKeyStarkWrapperDispatcher, IAddNewKeyStarkWrapperDispatcherTrait,
};
use zkstark_amaci_contracts::integrity_fact_registry::FACT_REGISTRY_MODE_DIRECT;
use zkstark_amaci_contracts::mock_integrity::{
    IMockIntegrityDispatcher, IMockIntegrityDispatcherTrait,
};
use zkstark_amaci_contracts::process_deactivate_wrapper::{
    IProcessDeactivateStarkWrapperDispatcher, IProcessDeactivateStarkWrapperDispatcherTrait,
};
use zkstark_amaci_contracts::process_messages_wrapper::{
    IProcessMessagesStarkWrapperDispatcher, IProcessMessagesStarkWrapperDispatcherTrait,
};
use zkstark_amaci_contracts::tally_votes_wrapper::{
    ITallyVotesStarkWrapperDispatcher, ITallyVotesStarkWrapperDispatcherTrait,
};

const ADD_NEW_KEY_PROGRAM_HASH: felt252 = 0x1111;
const PROCESS_MESSAGES_PROGRAM_HASH: felt252 = 0x2222;
const PROCESS_DEACTIVATE_PROGRAM_HASH: felt252 = 0x3333;
const TALLY_PROGRAM_HASH: felt252 = 0x1234;
const ATLANTIC_METADATA_PROGRAM_HASH: felt252 = 0x5555;
const VERIFIER_CONFIG_HASH: felt252 = 0x9abc;
const MIN_SECURITY_BITS: u32 = 80;
const PACKED_VALS: felt252 = 0x200000000;
const STATE_COMMITMENT: felt252 = 0x100;
const STATE_AFTER_KEY: felt252 = 0x110;
const STATE_AFTER_MESSAGES: felt252 = 0x120;
const INITIAL_DEACTIVATE_COMMITMENT: felt252 = 0x200;
const DEACTIVATE_AFTER_PROCESS: felt252 = 0x210;
const CURRENT_TALLY_COMMITMENT: felt252 = 0;
const NEW_TALLY_COMMITMENT: felt252 = 0x200;
const INPUT_HASH: felt252 = 0x300;
const KEY_NULLIFIER: felt252 = 0xabc;
const ADD_NEW_KEY_OUTPUT_HASH: felt252 = 0xa01;
const PROCESS_MESSAGES_OUTPUT_HASH: felt252 = 0xa02;
const PROCESS_DEACTIVATE_OUTPUT_HASH: felt252 = 0xa03;
const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b;
const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
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

fn deploy_wrapper(
    integrity: ContractAddress, bootloader_program_hash: felt252, verifier_config_hash: felt252,
) -> ITallyVotesStarkWrapperDispatcher {
    let contract = declare("TallyVotesStarkWrapper").unwrap().contract_class();
    let mut calldata = array![
        integrity.into(), TALLY_PROGRAM_HASH, bootloader_program_hash, verifier_config_hash,
        MIN_SECURITY_BITS.into(), PACKED_VALS, STATE_COMMITMENT, CURRENT_TALLY_COMMITMENT,
    ];

    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    ITallyVotesStarkWrapperDispatcher { contract_address }
}

fn deploy_add_new_key_wrapper(
    integrity: ContractAddress, verifier_config_hash: felt252,
) -> IAddNewKeyStarkWrapperDispatcher {
    let contract = declare("AddNewKeyStarkWrapper").unwrap().contract_class();
    let calldata = array![
        integrity.into(), FACT_REGISTRY_MODE_DIRECT, false.into(), verifier_config_hash,
        MIN_SECURITY_BITS.into(), ADD_NEW_KEY_PROGRAM_HASH, STATE_COMMITMENT,
    ];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    IAddNewKeyStarkWrapperDispatcher { contract_address }
}

fn deploy_process_deactivate_wrapper(
    integrity: ContractAddress, verifier_config_hash: felt252,
) -> IProcessDeactivateStarkWrapperDispatcher {
    let contract = declare("ProcessDeactivateStarkWrapper").unwrap().contract_class();
    let calldata = array![
        integrity.into(), FACT_REGISTRY_MODE_DIRECT, false.into(), verifier_config_hash,
        MIN_SECURITY_BITS.into(), PROCESS_DEACTIVATE_PROGRAM_HASH, STATE_COMMITMENT,
        INITIAL_DEACTIVATE_COMMITMENT,
    ];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    IProcessDeactivateStarkWrapperDispatcher { contract_address }
}

fn deploy_process_messages_wrapper(
    integrity: ContractAddress, verifier_config_hash: felt252,
) -> IProcessMessagesStarkWrapperDispatcher {
    let contract = declare("ProcessMessagesStarkWrapper").unwrap().contract_class();
    let calldata = array![
        integrity.into(), FACT_REGISTRY_MODE_DIRECT, false.into(), verifier_config_hash,
        MIN_SECURITY_BITS.into(), PROCESS_MESSAGES_PROGRAM_HASH, STATE_COMMITMENT,
        INITIAL_DEACTIVATE_COMMITMENT,
    ];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    IProcessMessagesStarkWrapperDispatcher { contract_address }
}

#[test]
fn submit_tally_fact_accepts_mock_integrity_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);

    assert(wrapper.get_current_tally_commitment() == NEW_TALLY_COMMITMENT, 'TALLY_NOT_UPDATED');
    assert(wrapper.get_processed_user_count() == 5, 'COUNT_NOT_UPDATED');
}

#[test]
fn submit_tally_fact_accepts_bootloaded_mock_integrity_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0x5678, 0);

    let fact_hash = wrapper.get_expected_bootloaded_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);

    assert(wrapper.get_current_tally_commitment() == NEW_TALLY_COMMITMENT, 'TALLY_NOT_UPDATED');
    assert(wrapper.get_processed_user_count() == 5, 'COUNT_NOT_UPDATED');
}

#[test]
fn submit_tally_fact_accepts_configured_verification_hash() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0, VERIFIER_CONFIG_HASH);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    let verification_hash = wrapper
        .get_expected_verification_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS - 1);
    integrity.set_verification_hash_valid(verification_hash, true);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);

    assert(wrapper.get_current_tally_commitment() == NEW_TALLY_COMMITMENT, 'TALLY_NOT_UPDATED');
    assert(wrapper.get_processed_user_count() == 5, 'COUNT_NOT_UPDATED');
}

#[test]
#[should_panic]
fn submit_tally_fact_rejects_unregistered_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);
}

#[test]
#[should_panic]
fn submit_tally_fact_rejects_insufficient_security_bits() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS - 1);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);
}

#[test]
#[should_panic]
fn submit_tally_fact_rejects_fact_for_different_output() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT + 1, INPUT_HASH, fact_hash);
}

#[test]
#[should_panic]
fn submit_tally_fact_rejects_stale_replay_after_state_update() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);
    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);
}

#[test]
#[should_panic]
fn submit_tally_fact_rejects_unregistered_verification_hash() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0, VERIFIER_CONFIG_HASH);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);
}

#[test]
fn submit_add_new_key_fact_accepts_mock_integrity_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_add_new_key_wrapper(integrity.contract_address, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(ADD_NEW_KEY_OUTPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper
        .submit_add_new_key_fact(
            KEY_NULLIFIER, STATE_AFTER_KEY, ADD_NEW_KEY_OUTPUT_HASH, fact_hash,
        );

    assert(wrapper.get_state_commitment() == STATE_AFTER_KEY, 'STATE_NOT_UPDATED');
    assert(wrapper.get_keys_added() == 1, 'KEY_COUNT_BAD');
    assert(wrapper.is_key_nullifier_used(KEY_NULLIFIER), 'KEY_NOT_USED');
}

#[test]
fn submit_add_new_key_atlantic_metadata_fact_accepts_mock_integrity_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_add_new_key_wrapper(integrity.contract_address, 0);
    let metadata_output = array![
        0, 0x99, 1, 21, ADD_NEW_KEY_PROGRAM_HASH, 0, 19, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, ADD_NEW_KEY_NATIVE_CIRCUIT_ID, STARKNET_POSEIDON_HASH_SCHEME,
        2, 4, 0x201, 0x202, KEY_NULLIFIER, 0x203, 0x204, 0x205, 0x206, 0x207, 0x208, 0x209, 0x20a,
        0x20b, 0x20c,
    ];
    let fact_hash = wrapper
        .get_expected_atlantic_metadata_fact_hash(
            ATLANTIC_METADATA_PROGRAM_HASH, metadata_output.span(),
        );
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper
        .submit_add_new_key_atlantic_metadata_fact(
            KEY_NULLIFIER,
            STATE_AFTER_KEY,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );

    assert(wrapper.get_state_commitment() == STATE_AFTER_KEY, 'STATE_NOT_UPDATED');
    assert(wrapper.get_keys_added() == 1, 'KEY_COUNT_BAD');
}

#[test]
#[should_panic]
fn submit_add_new_key_atlantic_metadata_fact_rejects_wrong_nullifier() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_add_new_key_wrapper(integrity.contract_address, 0);
    let metadata_output = array![
        0, 0x99, 1, 21, ADD_NEW_KEY_PROGRAM_HASH, 0, 19, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, ADD_NEW_KEY_NATIVE_CIRCUIT_ID, STARKNET_POSEIDON_HASH_SCHEME,
        2, 4, 0x201, 0x202, KEY_NULLIFIER + 1, 0x203, 0x204, 0x205, 0x206, 0x207, 0x208, 0x209,
        0x20a, 0x20b, 0x20c,
    ];
    let fact_hash = wrapper
        .get_expected_atlantic_metadata_fact_hash(
            ATLANTIC_METADATA_PROGRAM_HASH, metadata_output.span(),
        );
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper
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
fn submit_add_new_key_fact_rejects_duplicate_nullifier() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_add_new_key_wrapper(integrity.contract_address, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(ADD_NEW_KEY_OUTPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper
        .submit_add_new_key_fact(
            KEY_NULLIFIER, STATE_AFTER_KEY, ADD_NEW_KEY_OUTPUT_HASH, fact_hash,
        );
    wrapper
        .submit_add_new_key_fact(
            KEY_NULLIFIER, STATE_AFTER_KEY + 1, ADD_NEW_KEY_OUTPUT_HASH, fact_hash,
        );
}

#[test]
fn submit_process_messages_fact_accepts_mock_integrity_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_process_messages_wrapper(integrity.contract_address, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(PROCESS_MESSAGES_OUTPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper
        .submit_process_messages_fact(
            STATE_COMMITMENT,
            STATE_AFTER_MESSAGES,
            INITIAL_DEACTIVATE_COMMITMENT,
            PROCESS_MESSAGES_OUTPUT_HASH,
            fact_hash,
        );

    assert(wrapper.get_state_commitment() == STATE_AFTER_MESSAGES, 'STATE_NOT_UPDATED');
    assert(wrapper.get_deactivate_commitment() == INITIAL_DEACTIVATE_COMMITMENT, 'DEACT_CHANGED');
    assert(wrapper.get_message_batches_processed() == 1, 'MSG_COUNT_BAD');
}

#[test]
fn submit_process_messages_atlantic_metadata_fact_accepts_mock_integrity_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_process_messages_wrapper(integrity.contract_address, 0);
    let metadata_output = array![
        0, 0x99, 1, 18, PROCESS_MESSAGES_PROGRAM_HASH, 0, 16, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
        STARKNET_POSEIDON_HASH_SCHEME, 2, 1, 5, 0x301, 0x302, 0x303, 0x304, STATE_COMMITMENT,
        STATE_AFTER_MESSAGES, INITIAL_DEACTIVATE_COMMITMENT, 0x305, 0x306,
    ];
    let fact_hash = wrapper
        .get_expected_atlantic_metadata_fact_hash(
            ATLANTIC_METADATA_PROGRAM_HASH, metadata_output.span(),
        );
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper
        .submit_process_messages_atlantic_metadata_fact(
            STATE_COMMITMENT,
            STATE_AFTER_MESSAGES,
            INITIAL_DEACTIVATE_COMMITMENT,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );

    assert(wrapper.get_state_commitment() == STATE_AFTER_MESSAGES, 'STATE_NOT_UPDATED');
    assert(wrapper.get_message_batches_processed() == 1, 'MSG_COUNT_BAD');
}

#[test]
#[should_panic]
fn submit_process_messages_fact_rejects_stale_state() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_process_messages_wrapper(integrity.contract_address, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(PROCESS_MESSAGES_OUTPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper
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
fn submit_process_messages_atlantic_metadata_fact_rejects_wrong_new_state_output() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_process_messages_wrapper(integrity.contract_address, 0);
    let metadata_output = array![
        0, 0x99, 1, 18, PROCESS_MESSAGES_PROGRAM_HASH, 0, 16, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
        STARKNET_POSEIDON_HASH_SCHEME, 2, 1, 5, 0x301, 0x302, 0x303, 0x304, STATE_COMMITMENT,
        STATE_AFTER_MESSAGES + 1, INITIAL_DEACTIVATE_COMMITMENT, 0x305, 0x306,
    ];
    let fact_hash = wrapper
        .get_expected_atlantic_metadata_fact_hash(
            ATLANTIC_METADATA_PROGRAM_HASH, metadata_output.span(),
        );
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper
        .submit_process_messages_atlantic_metadata_fact(
            STATE_COMMITMENT,
            STATE_AFTER_MESSAGES,
            INITIAL_DEACTIVATE_COMMITMENT,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );
}

#[test]
fn submit_process_deactivate_fact_accepts_mock_integrity_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_process_deactivate_wrapper(integrity.contract_address, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(PROCESS_DEACTIVATE_OUTPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper
        .submit_process_deactivate_fact(
            INITIAL_DEACTIVATE_COMMITMENT,
            DEACTIVATE_AFTER_PROCESS,
            STATE_COMMITMENT,
            PROCESS_DEACTIVATE_OUTPUT_HASH,
            fact_hash,
        );

    assert(wrapper.get_deactivate_commitment() == DEACTIVATE_AFTER_PROCESS, 'DEACT_NOT_UPDATED');
    assert(wrapper.get_deactivate_batches_processed() == 1, 'DEACT_COUNT_BAD');
}

#[test]
fn submit_process_deactivate_atlantic_metadata_fact_accepts_mock_integrity_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_process_deactivate_wrapper(integrity.contract_address, 0);
    let metadata_output = array![
        0, 0x99, 1, 18, PROCESS_DEACTIVATE_PROGRAM_HASH, 0, 16, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID,
        STARKNET_POSEIDON_HASH_SCHEME, 2, 4, 5, 0x401, 0x402, 0x403, 0x404,
        INITIAL_DEACTIVATE_COMMITMENT, DEACTIVATE_AFTER_PROCESS, STATE_COMMITMENT, 0x406, 0x407,
    ];
    let fact_hash = wrapper
        .get_expected_atlantic_metadata_fact_hash(
            ATLANTIC_METADATA_PROGRAM_HASH, metadata_output.span(),
        );
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper
        .submit_process_deactivate_atlantic_metadata_fact(
            INITIAL_DEACTIVATE_COMMITMENT,
            DEACTIVATE_AFTER_PROCESS,
            STATE_COMMITMENT,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );

    assert(wrapper.get_deactivate_commitment() == DEACTIVATE_AFTER_PROCESS, 'DEACT_NOT_UPDATED');
    assert(wrapper.get_deactivate_batches_processed() == 1, 'DEACT_COUNT_BAD');
}

#[test]
#[should_panic]
fn submit_process_deactivate_atlantic_metadata_fact_rejects_wrong_state_output() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_process_deactivate_wrapper(integrity.contract_address, 0);
    let metadata_output = array![
        0, 0x99, 1, 18, PROCESS_DEACTIVATE_PROGRAM_HASH, 0, 16, PUBLIC_OUTPUT_MAGIC,
        NATIVE_PUBLIC_OUTPUT_VERSION, PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID,
        STARKNET_POSEIDON_HASH_SCHEME, 2, 4, 5, 0x401, 0x402, 0x403, 0x404,
        INITIAL_DEACTIVATE_COMMITMENT, DEACTIVATE_AFTER_PROCESS, STATE_COMMITMENT + 1, 0x406, 0x407,
    ];
    let fact_hash = wrapper
        .get_expected_atlantic_metadata_fact_hash(
            ATLANTIC_METADATA_PROGRAM_HASH, metadata_output.span(),
        );
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper
        .submit_process_deactivate_atlantic_metadata_fact(
            INITIAL_DEACTIVATE_COMMITMENT,
            DEACTIVATE_AFTER_PROCESS,
            STATE_COMMITMENT,
            ATLANTIC_METADATA_PROGRAM_HASH,
            metadata_output.span(),
            fact_hash,
        );
}
