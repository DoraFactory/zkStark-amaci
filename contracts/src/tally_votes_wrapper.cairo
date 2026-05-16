#[starknet::interface]
pub trait IIntegrity<TContractState> {
    fn is_fact_hash_valid_with_security(
        self: @TContractState, fact_hash: felt252, security_bits: u32,
    ) -> bool;
    fn is_verification_hash_valid(self: @TContractState, verification_hash: felt252) -> bool;
}

#[starknet::interface]
pub trait ITallyVotesStarkWrapper<TContractState> {
    fn get_current_tally_commitment(self: @TContractState) -> felt252;
    fn get_processed_user_count(self: @TContractState) -> felt252;
    fn get_expected_plain_fact_hash(
        self: @TContractState, new_tally_commitment: felt252, input_hash: felt252,
    ) -> felt252;
    fn get_expected_bootloaded_fact_hash(
        self: @TContractState, new_tally_commitment: felt252, input_hash: felt252,
    ) -> felt252;
    fn get_expected_verification_hash(
        self: @TContractState, new_tally_commitment: felt252, input_hash: felt252,
    ) -> felt252;
    fn submit_tally_fact(
        ref self: TContractState,
        new_tally_commitment: felt252,
        input_hash: felt252,
        fact_hash: felt252,
    );
}

#[starknet::contract]
pub mod TallyVotesStarkWrapper {
    use core::poseidon::{hades_permutation, poseidon_hash_span};
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use super::{IIntegrityDispatcher, IIntegrityDispatcherTrait};

    const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b; // MACISTARK
    const PUBLIC_OUTPUT_VERSION: felt252 = 2;
    const TALLY_VOTES_CIRCUIT_ID: felt252 =
        0x414d4143495f54414c4c595f4e4154495645; // AMACI_TALLY_NATIVE
    const STARKNET_POSEIDON_HASH_SCHEME: felt252 =
        0x535441524b4e45545f504f534549444f4e; // STARKNET_POSEIDON
    const STATE_TREE_DEPTH: felt252 = 2;
    const INT_STATE_TREE_DEPTH: felt252 = 1;
    const VOTE_OPTION_TREE_DEPTH: felt252 = 1;
    const BOOTLOADER_TASKS: felt252 = 1;
    const BOOTLOADER_CHILD_OUTPUT_WITH_METADATA_LEN: felt252 = 14;

    #[storage]
    struct Storage {
        integrity: ContractAddress,
        tally_program_hash: felt252,
        bootloader_program_hash: felt252,
        verifier_config_hash: felt252,
        min_security_bits: u32,
        packed_vals: felt252,
        state_commitment: felt252,
        current_tally_commitment: felt252,
        processed_user_count: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TallyFactAccepted: TallyFactAccepted,
    }

    #[derive(Drop, starknet::Event)]
    struct TallyFactAccepted {
        fact_hash: felt252,
        verification_hash: felt252,
        new_tally_commitment: felt252,
        input_hash: felt252,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        integrity: ContractAddress,
        tally_program_hash: felt252,
        bootloader_program_hash: felt252,
        verifier_config_hash: felt252,
        min_security_bits: u32,
        packed_vals: felt252,
        state_commitment: felt252,
        current_tally_commitment: felt252,
    ) {
        self.integrity.write(integrity);
        self.tally_program_hash.write(tally_program_hash);
        self.bootloader_program_hash.write(bootloader_program_hash);
        self.verifier_config_hash.write(verifier_config_hash);
        self.min_security_bits.write(min_security_bits);
        self.packed_vals.write(packed_vals);
        self.state_commitment.write(state_commitment);
        self.current_tally_commitment.write(current_tally_commitment);
        self.processed_user_count.write(0);
    }

    #[abi(embed_v0)]
    impl TallyVotesStarkWrapperImpl of super::ITallyVotesStarkWrapper<ContractState> {
        fn get_current_tally_commitment(self: @ContractState) -> felt252 {
            self.current_tally_commitment.read()
        }

        fn get_processed_user_count(self: @ContractState) -> felt252 {
            self.processed_user_count.read()
        }

        fn get_expected_plain_fact_hash(
            self: @ContractState, new_tally_commitment: felt252, input_hash: felt252,
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
            self: @ContractState, new_tally_commitment: felt252, input_hash: felt252,
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

        fn get_expected_verification_hash(
            self: @ContractState, new_tally_commitment: felt252, input_hash: felt252,
        ) -> felt252 {
            let bootloader_program_hash = self.bootloader_program_hash.read();
            let fact_hash = if bootloader_program_hash == 0 {
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
            verification_hash(
                fact_hash, self.verifier_config_hash.read(), self.min_security_bits.read(),
            )
        }

        fn submit_tally_fact(
            ref self: ContractState,
            new_tally_commitment: felt252,
            input_hash: felt252,
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
            let verifier_config_hash = self.verifier_config_hash.read();
            let expected_verification_hash = verification_hash(
                fact_hash, verifier_config_hash, self.min_security_bits.read(),
            );
            let valid = if verifier_config_hash == 0 {
                integrity.is_fact_hash_valid_with_security(fact_hash, self.min_security_bits.read())
            } else {
                integrity.is_verification_hash_valid(expected_verification_hash)
            };
            assert(valid, 'INVALID_INTEGRITY_FACT');

            self.current_tally_commitment.write(new_tally_commitment);
            self.processed_user_count.write(self.processed_user_count.read() + 5);
            self
                .emit(
                    TallyFactAccepted {
                        fact_hash,
                        verification_hash: expected_verification_hash,
                        new_tally_commitment,
                        input_hash,
                    },
                );
        }
    }

    fn public_output_hash(
        packed_vals: felt252,
        state_commitment: felt252,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
        input_hash: felt252,
    ) -> felt252 {
        poseidon_hash_span(
            [
                PUBLIC_OUTPUT_MAGIC, PUBLIC_OUTPUT_VERSION, TALLY_VOTES_CIRCUIT_ID,
                STARKNET_POSEIDON_HASH_SCHEME, STATE_TREE_DEPTH, INT_STATE_TREE_DEPTH,
                VOTE_OPTION_TREE_DEPTH, packed_vals, state_commitment, current_tally_commitment,
                new_tally_commitment, input_hash,
            ]
                .span(),
        )
    }

    fn plain_fact_hash(
        tally_program_hash: felt252,
        packed_vals: felt252,
        state_commitment: felt252,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
        input_hash: felt252,
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
        packed_vals: felt252,
        state_commitment: felt252,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
        input_hash: felt252,
    ) -> felt252 {
        poseidon_hash_span(
            [
                BOOTLOADER_TASKS, BOOTLOADER_CHILD_OUTPUT_WITH_METADATA_LEN, tally_program_hash,
                PUBLIC_OUTPUT_MAGIC, PUBLIC_OUTPUT_VERSION, TALLY_VOTES_CIRCUIT_ID,
                STARKNET_POSEIDON_HASH_SCHEME, STATE_TREE_DEPTH, INT_STATE_TREE_DEPTH,
                VOTE_OPTION_TREE_DEPTH, packed_vals, state_commitment, current_tally_commitment,
                new_tally_commitment, input_hash,
            ]
                .span(),
        )
    }

    fn bootloaded_fact_hash(
        bootloader_program_hash: felt252,
        tally_program_hash: felt252,
        packed_vals: felt252,
        state_commitment: felt252,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
        input_hash: felt252,
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

    fn verification_hash(
        fact_hash: felt252, verifier_config_hash: felt252, security_bits: u32,
    ) -> felt252 {
        poseidon_hash_span([fact_hash, verifier_config_hash, security_bits.into()].span())
    }

    #[cfg(test)]
    mod tests {
        use super::{
            bootloaded_fact_hash, bootloaded_output_hash, plain_fact_hash, public_output_hash,
        };

        #[test]
        fn public_output_hash_matches_starknet_js_vector() {
            let actual = public_output_hash(5, 6, 7, 8, 9);
            assert(
                actual == 0x45655aefd6096c7862f87b847a88246ee4180069c810b657443c9b6ab4a956,
                'OUTPUT_HASH_VECTOR_MISMATCH',
            );
        }

        #[test]
        fn plain_fact_hash_matches_starknet_js_vector() {
            let actual = plain_fact_hash(0x1234, 5, 6, 7, 8, 9);
            assert(
                actual == 0x477789976d748f724ddabf99cffdfa11f30420fb908e9ad4ab0b34a0aabcd99,
                'FACT_HASH_VECTOR_MISMATCH',
            );
        }

        #[test]
        fn bootloaded_fact_hash_matches_starknet_js_vector() {
            let output_hash = bootloaded_output_hash(0x1234, 5, 6, 7, 8, 9);
            assert(
                output_hash == 0x228fcb4d4f2f21d640481335a36ae90e6b2c6342e4d8684d32e6f33a0dcc28c,
                'BOOT_OUTPUT_HASH_MISMATCH',
            );

            let fact_hash = bootloaded_fact_hash(0x5678, 0x1234, 5, 6, 7, 8, 9);
            assert(
                fact_hash == 0x775e9f4544c95b87bac17eedc82b58f99c490493497ebb6b9c143424b26d6a6,
                'BOOT_FACT_HASH_MISMATCH',
            );
        }
    }
}
