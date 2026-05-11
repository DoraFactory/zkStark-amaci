use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use zkstark_amaci_contracts::mock_integrity::{
    IMockIntegrityDispatcher, IMockIntegrityDispatcherTrait,
};
use zkstark_amaci_contracts::tally_votes_wrapper::{
    ITallyVotesStarkWrapperDispatcher, ITallyVotesStarkWrapperDispatcherTrait,
};

const TALLY_PROGRAM_HASH: felt252 = 0x1234;
const MIN_SECURITY_BITS: u32 = 80;
const PACKED_VALS: u256 = 0x200000000;
const STATE_COMMITMENT: u256 = 0x100;
const CURRENT_TALLY_COMMITMENT: u256 = 0;
const NEW_TALLY_COMMITMENT: u256 = 0x200;
const INPUT_HASH: u256 = 0x300;

fn append_u256(ref calldata: Array<felt252>, value: u256) {
    calldata.append(value.low.into());
    calldata.append(value.high.into());
}

fn deploy_mock_integrity() -> IMockIntegrityDispatcher {
    let contract = declare("MockIntegrity").unwrap().contract_class();
    let calldata = array![];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    IMockIntegrityDispatcher { contract_address }
}

fn deploy_wrapper(
    integrity: ContractAddress, bootloader_program_hash: felt252,
) -> ITallyVotesStarkWrapperDispatcher {
    let contract = declare("TallyVotesStarkWrapper").unwrap().contract_class();
    let mut calldata = array![
        integrity.into(), TALLY_PROGRAM_HASH, bootloader_program_hash, MIN_SECURITY_BITS.into(),
    ];
    append_u256(ref calldata, PACKED_VALS);
    append_u256(ref calldata, STATE_COMMITMENT);
    append_u256(ref calldata, CURRENT_TALLY_COMMITMENT);

    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    ITallyVotesStarkWrapperDispatcher { contract_address }
}

#[test]
fn submit_tally_fact_accepts_mock_integrity_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);

    assert(wrapper.get_current_tally_commitment() == NEW_TALLY_COMMITMENT, 'TALLY_NOT_UPDATED');
    assert(wrapper.get_processed_user_count() == 5_u256, 'COUNT_NOT_UPDATED');
}

#[test]
fn submit_tally_fact_accepts_bootloaded_mock_integrity_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0x5678);

    let fact_hash = wrapper.get_expected_bootloaded_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);

    assert(wrapper.get_current_tally_commitment() == NEW_TALLY_COMMITMENT, 'TALLY_NOT_UPDATED');
    assert(wrapper.get_processed_user_count() == 5_u256, 'COUNT_NOT_UPDATED');
}

#[test]
#[should_panic]
fn submit_tally_fact_rejects_unregistered_fact() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);
}

#[test]
#[should_panic]
fn submit_tally_fact_rejects_insufficient_security_bits() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS - 1);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);
}

#[test]
#[should_panic]
fn submit_tally_fact_rejects_fact_for_different_output() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT + 1_u256, INPUT_HASH, fact_hash);
}

#[test]
#[should_panic]
fn submit_tally_fact_rejects_stale_replay_after_state_update() {
    let integrity = deploy_mock_integrity();
    let wrapper = deploy_wrapper(integrity.contract_address, 0);

    let fact_hash = wrapper.get_expected_plain_fact_hash(NEW_TALLY_COMMITMENT, INPUT_HASH);
    integrity.set_fact_security_bits(fact_hash, MIN_SECURITY_BITS);

    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);
    wrapper.submit_tally_fact(NEW_TALLY_COMMITMENT, INPUT_HASH, fact_hash);
}
