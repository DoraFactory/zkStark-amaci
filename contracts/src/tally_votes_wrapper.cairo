#[starknet::interface]
pub trait IIntegrity<TContractState> {
    fn is_fact_hash_valid_with_security(
        self: @TContractState, fact_hash: felt252, security_bits: u32,
    ) -> bool;
}

#[starknet::interface]
pub trait ITallyVotesStarkWrapper<TContractState> {
    fn get_current_tally_commitment(self: @TContractState) -> u256;
    fn get_processed_user_count(self: @TContractState) -> u256;
    fn get_expected_plain_fact_hash(
        self: @TContractState, new_tally_commitment: u256, input_hash: u256,
    ) -> felt252;
    fn get_expected_bootloaded_fact_hash(
        self: @TContractState, new_tally_commitment: u256, input_hash: u256,
    ) -> felt252;
    fn submit_tally_fact(
        ref self: TContractState, new_tally_commitment: u256, input_hash: u256, fact_hash: felt252,
    );
}

#[starknet::contract]
pub mod TallyVotesStarkWrapper {
    use core::poseidon::{hades_permutation, poseidon_hash_span};
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use super::{IIntegrityDispatcher, IIntegrityDispatcherTrait};

    const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b; // MACISTARK
    const PUBLIC_OUTPUT_VERSION: felt252 = 1;
    const TALLY_VOTES_CIRCUIT_ID: felt252 =
        0x414d4143495f54414c4c595f564f544553; // AMACI_TALLY_VOTES
    const STATE_TREE_DEPTH: felt252 = 2;
    const INT_STATE_TREE_DEPTH: felt252 = 1;
    const VOTE_OPTION_TREE_DEPTH: felt252 = 1;
    const BOOTLOADER_TASKS: felt252 = 1;
    const BOOTLOADER_CHILD_OUTPUT_WITH_METADATA_LEN: felt252 = 18;

    #[storage]
    struct Storage {
        integrity: ContractAddress,
        tally_program_hash: felt252,
        bootloader_program_hash: felt252,
        min_security_bits: u32,
        packed_vals: u256,
        state_commitment: u256,
        current_tally_commitment: u256,
        processed_user_count: u256,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TallyFactAccepted: TallyFactAccepted,
    }

    #[derive(Drop, starknet::Event)]
    struct TallyFactAccepted {
        fact_hash: felt252,
        new_tally_commitment: u256,
        input_hash: u256,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        integrity: ContractAddress,
        tally_program_hash: felt252,
        bootloader_program_hash: felt252,
        min_security_bits: u32,
        packed_vals: u256,
        state_commitment: u256,
        current_tally_commitment: u256,
    ) {
        self.integrity.write(integrity);
        self.tally_program_hash.write(tally_program_hash);
        self.bootloader_program_hash.write(bootloader_program_hash);
        self.min_security_bits.write(min_security_bits);
        self.packed_vals.write(packed_vals);
        self.state_commitment.write(state_commitment);
        self.current_tally_commitment.write(current_tally_commitment);
        self.processed_user_count.write(0);
    }

    #[abi(embed_v0)]
    impl TallyVotesStarkWrapperImpl of super::ITallyVotesStarkWrapper<ContractState> {
        fn get_current_tally_commitment(self: @ContractState) -> u256 {
            self.current_tally_commitment.read()
        }

        fn get_processed_user_count(self: @ContractState) -> u256 {
            self.processed_user_count.read()
        }

        fn get_expected_plain_fact_hash(
            self: @ContractState, new_tally_commitment: u256, input_hash: u256,
        ) -> felt252 {
            plain_fact_hash(
                self.tally_program_hash.read(),
                self.packed_vals.read(),
                self.state_commitment.read(),
                self.current_tally_commitment.read(),
                new_tally_commitment,
                input_hash,
            )
        }

        fn get_expected_bootloaded_fact_hash(
            self: @ContractState, new_tally_commitment: u256, input_hash: u256,
        ) -> felt252 {
            bootloaded_fact_hash(
                self.bootloader_program_hash.read(),
                self.tally_program_hash.read(),
                self.packed_vals.read(),
                self.state_commitment.read(),
                self.current_tally_commitment.read(),
                new_tally_commitment,
                input_hash,
            )
        }

        fn submit_tally_fact(
            ref self: ContractState,
            new_tally_commitment: u256,
            input_hash: u256,
            fact_hash: felt252,
        ) {
            let bootloader_program_hash = self.bootloader_program_hash.read();
            let expected_fact_hash = if bootloader_program_hash == 0 {
                plain_fact_hash(
                    self.tally_program_hash.read(),
                    self.packed_vals.read(),
                    self.state_commitment.read(),
                    self.current_tally_commitment.read(),
                    new_tally_commitment,
                    input_hash,
                )
            } else {
                bootloaded_fact_hash(
                    bootloader_program_hash,
                    self.tally_program_hash.read(),
                    self.packed_vals.read(),
                    self.state_commitment.read(),
                    self.current_tally_commitment.read(),
                    new_tally_commitment,
                    input_hash,
                )
            };
            assert(fact_hash == expected_fact_hash, 'FACT_HASH_BINDING_MISMATCH');

            let integrity = IIntegrityDispatcher { contract_address: self.integrity.read() };
            let valid = integrity
                .is_fact_hash_valid_with_security(fact_hash, self.min_security_bits.read());
            assert(valid, 'INVALID_INTEGRITY_FACT');

            self.current_tally_commitment.write(new_tally_commitment);
            self.processed_user_count.write(self.processed_user_count.read() + 5_u256);
            self.emit(TallyFactAccepted { fact_hash, new_tally_commitment, input_hash });
        }
    }

    fn u256_low(value: u256) -> felt252 {
        value.low.into()
    }

    fn u256_high(value: u256) -> felt252 {
        value.high.into()
    }

    fn public_output_hash(
        packed_vals: u256,
        state_commitment: u256,
        current_tally_commitment: u256,
        new_tally_commitment: u256,
        input_hash: u256,
    ) -> felt252 {
        poseidon_hash_span(
            [
                PUBLIC_OUTPUT_MAGIC, PUBLIC_OUTPUT_VERSION, TALLY_VOTES_CIRCUIT_ID,
                STATE_TREE_DEPTH, INT_STATE_TREE_DEPTH, VOTE_OPTION_TREE_DEPTH,
                u256_low(packed_vals), u256_high(packed_vals), u256_low(state_commitment),
                u256_high(state_commitment), u256_low(current_tally_commitment),
                u256_high(current_tally_commitment), u256_low(new_tally_commitment),
                u256_high(new_tally_commitment), u256_low(input_hash), u256_high(input_hash),
            ]
                .span(),
        )
    }

    fn plain_fact_hash(
        tally_program_hash: felt252,
        packed_vals: u256,
        state_commitment: u256,
        current_tally_commitment: u256,
        new_tally_commitment: u256,
        input_hash: u256,
    ) -> felt252 {
        let output_hash = public_output_hash(
            packed_vals,
            state_commitment,
            current_tally_commitment,
            new_tally_commitment,
            input_hash,
        );
        poseidon_pair_hash(tally_program_hash, output_hash)
    }

    fn bootloaded_output_hash(
        tally_program_hash: felt252,
        packed_vals: u256,
        state_commitment: u256,
        current_tally_commitment: u256,
        new_tally_commitment: u256,
        input_hash: u256,
    ) -> felt252 {
        poseidon_hash_span(
            [
                BOOTLOADER_TASKS, BOOTLOADER_CHILD_OUTPUT_WITH_METADATA_LEN, tally_program_hash,
                PUBLIC_OUTPUT_MAGIC, PUBLIC_OUTPUT_VERSION, TALLY_VOTES_CIRCUIT_ID,
                STATE_TREE_DEPTH, INT_STATE_TREE_DEPTH, VOTE_OPTION_TREE_DEPTH,
                u256_low(packed_vals), u256_high(packed_vals), u256_low(state_commitment),
                u256_high(state_commitment), u256_low(current_tally_commitment),
                u256_high(current_tally_commitment), u256_low(new_tally_commitment),
                u256_high(new_tally_commitment), u256_low(input_hash), u256_high(input_hash),
            ]
                .span(),
        )
    }

    fn bootloaded_fact_hash(
        bootloader_program_hash: felt252,
        tally_program_hash: felt252,
        packed_vals: u256,
        state_commitment: u256,
        current_tally_commitment: u256,
        new_tally_commitment: u256,
        input_hash: u256,
    ) -> felt252 {
        let output_hash = bootloaded_output_hash(
            tally_program_hash,
            packed_vals,
            state_commitment,
            current_tally_commitment,
            new_tally_commitment,
            input_hash,
        );
        poseidon_pair_hash(bootloader_program_hash, output_hash)
    }

    fn poseidon_pair_hash(left: felt252, right: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(left, right, 2);
        result
    }

    #[cfg(test)]
    mod tests {
        use super::{
            bootloaded_fact_hash, bootloaded_output_hash, plain_fact_hash, public_output_hash,
        };

        #[test]
        fn public_output_hash_matches_starknet_js_vector() {
            let actual = public_output_hash(5_u256, 6_u256, 7_u256, 8_u256, 9_u256);
            assert(
                actual == 0x4de57ed602c25ea4282cf6a3fce46cf4de111226b7be4a72b6a4b114f29cc38,
                'OUTPUT_HASH_VECTOR_MISMATCH',
            );
        }

        #[test]
        fn plain_fact_hash_matches_starknet_js_vector() {
            let actual = plain_fact_hash(0x1234, 5_u256, 6_u256, 7_u256, 8_u256, 9_u256);
            assert(
                actual == 0x731c2682f368d36425f7be148ec110ac9b2738c2d4db1bf67b0323d33460bd3,
                'FACT_HASH_VECTOR_MISMATCH',
            );
        }

        #[test]
        fn bootloaded_fact_hash_matches_starknet_js_vector() {
            let output_hash = bootloaded_output_hash(
                0x1234, 5_u256, 6_u256, 7_u256, 8_u256, 9_u256,
            );
            assert(
                output_hash == 0x6dfdeb0e22dd99b6c40a639531e25946f1677317f593f3333fe7a42854f3e0,
                'BOOT_OUTPUT_HASH_MISMATCH',
            );

            let fact_hash = bootloaded_fact_hash(
                0x5678, 0x1234, 5_u256, 6_u256, 7_u256, 8_u256, 9_u256,
            );
            assert(
                fact_hash == 0x6ebbe1fec695cc55aa10265b5537ae62ba19fa3419031db7cd05d592f20f0d0,
                'BOOT_FACT_HASH_MISMATCH',
            );
        }
    }
}
