#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct VerifierConfiguration {
    pub layout: felt252,
    pub hasher: felt252,
    pub stone_version: felt252,
    pub memory_verification: felt252,
}

#[derive(Drop, Copy, Serde)]
pub struct VerificationListElement {
    pub verification_hash: felt252,
    pub security_bits: u32,
    pub verifier_config: VerifierConfiguration,
}

#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct Verification {
    pub fact_hash: felt252,
    pub security_bits: u32,
    pub verifier_config: VerifierConfiguration,
}

#[starknet::interface]
pub trait IFactRegistry<TContractState> {
    fn get_all_verifications_for_fact_hash(
        self: @TContractState, fact_hash: felt252,
    ) -> Array<VerificationListElement>;
    fn get_verification(self: @TContractState, verification_hash: felt252) -> Option<Verification>;
}

#[starknet::interface]
pub trait IFactRegistryWithMocking<TContractState> {
    fn get_all_verifications_for_fact_hash(
        self: @TContractState, fact_hash: felt252, is_mocked: bool,
    ) -> Span<VerificationListElement>;
    fn get_verification(
        self: @TContractState, verification_hash: felt252, is_mocked: bool,
    ) -> Option<Verification>;
}

pub const FACT_REGISTRY_MODE_DIRECT: felt252 = 0;
pub const FACT_REGISTRY_MODE_SATELLITE: felt252 = 1;

pub fn empty_verifier_configuration() -> VerifierConfiguration {
    VerifierConfiguration { layout: 0, hasher: 0, stone_version: 0, memory_verification: 0 }
}

pub fn is_fact_hash_valid_with_security(
    fact_registry: starknet::ContractAddress,
    fact_registry_mode: felt252,
    is_fact_mocked: bool,
    fact_hash: felt252,
    security_bits: u32,
) -> bool {
    let verifications = if fact_registry_mode == FACT_REGISTRY_MODE_SATELLITE {
        IFactRegistryWithMockingDispatcher { contract_address: fact_registry }
            .get_all_verifications_for_fact_hash(fact_hash, is_fact_mocked)
    } else {
        assert(fact_registry_mode == FACT_REGISTRY_MODE_DIRECT, 'BAD_REGISTRY_MODE');
        IFactRegistryDispatcher { contract_address: fact_registry }
            .get_all_verifications_for_fact_hash(fact_hash)
            .span()
    };

    let mut result = false;
    for verification in verifications {
        if (*verification).security_bits >= security_bits {
            result = true;
            break;
        }
    }
    result
}

pub fn is_verification_hash_valid(
    fact_registry: starknet::ContractAddress,
    fact_registry_mode: felt252,
    is_fact_mocked: bool,
    verification_hash: felt252,
) -> bool {
    if fact_registry_mode == FACT_REGISTRY_MODE_SATELLITE {
        IFactRegistryWithMockingDispatcher { contract_address: fact_registry }
            .get_verification(verification_hash, is_fact_mocked)
            .is_some()
    } else {
        assert(fact_registry_mode == FACT_REGISTRY_MODE_DIRECT, 'BAD_REGISTRY_MODE');
        IFactRegistryDispatcher { contract_address: fact_registry }
            .get_verification(verification_hash)
            .is_some()
    }
}
