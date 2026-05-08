#[starknet::interface]
pub trait IMockIntegrity<TContractState> {
    fn set_fact_security_bits(ref self: TContractState, fact_hash: felt252, security_bits: u32);
    fn get_fact_security_bits(self: @TContractState, fact_hash: felt252) -> u32;
}

#[starknet::contract]
pub mod MockIntegrity {
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};

    #[storage]
    struct Storage {
        fact_security_bits: Map<felt252, u32>,
    }

    #[abi(embed_v0)]
    impl IntegrityImpl of crate::tally_votes_wrapper::IIntegrity<ContractState> {
        fn is_fact_hash_valid_with_security(
            self: @ContractState, fact_hash: felt252, security_bits: u32,
        ) -> bool {
            self.fact_security_bits.read(fact_hash) >= security_bits
        }
    }

    #[abi(embed_v0)]
    impl MockIntegrityImpl of super::IMockIntegrity<ContractState> {
        fn set_fact_security_bits(ref self: ContractState, fact_hash: felt252, security_bits: u32) {
            self.fact_security_bits.write(fact_hash, security_bits);
        }

        fn get_fact_security_bits(self: @ContractState, fact_hash: felt252) -> u32 {
            self.fact_security_bits.read(fact_hash)
        }
    }
}
