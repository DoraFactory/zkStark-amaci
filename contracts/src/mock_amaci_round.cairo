#[starknet::interface]
pub trait IMockAmaciRound<TContractState> {
    fn set_program_hash_allowed(ref self: TContractState, program_hash: felt252, allowed: bool);
    fn is_program_hash_allowed(self: @TContractState, program_hash: felt252) -> bool;
    fn get_state_commitment(self: @TContractState) -> felt252;
    fn get_deactivate_commitment(self: @TContractState) -> felt252;
    fn get_tally_commitment(self: @TContractState) -> felt252;
    fn get_keys_added(self: @TContractState) -> felt252;
    fn get_message_batches_processed(self: @TContractState) -> felt252;
    fn get_deactivate_batches_processed(self: @TContractState) -> felt252;
    fn get_total_facts_accepted(self: @TContractState) -> felt252;
    fn get_tally_submitted(self: @TContractState) -> bool;
    fn get_expected_fact_hash(
        self: @TContractState, program_hash: felt252, public_output_hash: felt252,
    ) -> felt252;
    fn get_expected_verification_hash(self: @TContractState, fact_hash: felt252) -> felt252;
    fn submit_operation_fact(
        ref self: TContractState,
        operation_id: felt252,
        program_hash: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
    );
    fn submit_add_new_key_fact(
        ref self: TContractState,
        key_nullifier: felt252,
        new_state_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
    );
    fn submit_process_messages_fact(
        ref self: TContractState,
        current_state_commitment: felt252,
        new_state_commitment: felt252,
        current_deactivate_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
    );
    fn submit_process_deactivate_fact(
        ref self: TContractState,
        current_deactivate_commitment: felt252,
        new_deactivate_commitment: felt252,
        current_state_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
    );
    fn submit_tally_fact(
        ref self: TContractState,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
        current_state_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
    );
}

#[starknet::contract]
pub mod MockAmaciRound {
    use core::poseidon::{hades_permutation, poseidon_hash_span};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use crate::tally_votes_wrapper::{IIntegrityDispatcher, IIntegrityDispatcherTrait};

    #[storage]
    struct Storage {
        admin: ContractAddress,
        integrity: ContractAddress,
        verifier_config_hash: felt252,
        min_security_bits: u32,
        add_new_key_program_hash: felt252,
        process_messages_program_hash: felt252,
        process_deactivate_program_hash: felt252,
        tally_program_hash: felt252,
        allowed_program_hashes: Map<felt252, bool>,
        used_key_nullifiers: Map<felt252, bool>,
        state_commitment: felt252,
        deactivate_commitment: felt252,
        tally_commitment: felt252,
        keys_added: felt252,
        message_batches_processed: felt252,
        deactivate_batches_processed: felt252,
        total_facts_accepted: felt252,
        tally_submitted: bool,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ProgramHashAllowedSet: ProgramHashAllowedSet,
        OperationFactAccepted: OperationFactAccepted,
        AddNewKeyFactAccepted: AddNewKeyFactAccepted,
        ProcessMessagesFactAccepted: ProcessMessagesFactAccepted,
        ProcessDeactivateFactAccepted: ProcessDeactivateFactAccepted,
        TallyFactAccepted: TallyFactAccepted,
    }

    #[derive(Drop, starknet::Event)]
    struct ProgramHashAllowedSet {
        program_hash: felt252,
        allowed: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct OperationFactAccepted {
        operation_id: felt252,
        program_hash: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
        verification_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct AddNewKeyFactAccepted {
        key_nullifier: felt252,
        new_state_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
        verification_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ProcessMessagesFactAccepted {
        old_state_commitment: felt252,
        new_state_commitment: felt252,
        deactivate_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
        verification_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ProcessDeactivateFactAccepted {
        old_deactivate_commitment: felt252,
        new_deactivate_commitment: felt252,
        state_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
        verification_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct TallyFactAccepted {
        old_tally_commitment: felt252,
        new_tally_commitment: felt252,
        state_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
        verification_hash: felt252,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        admin: ContractAddress,
        integrity: ContractAddress,
        verifier_config_hash: felt252,
        min_security_bits: u32,
        add_new_key_program_hash: felt252,
        process_messages_program_hash: felt252,
        process_deactivate_program_hash: felt252,
        tally_program_hash: felt252,
        initial_state_commitment: felt252,
        initial_deactivate_commitment: felt252,
        initial_tally_commitment: felt252,
    ) {
        self.admin.write(admin);
        self.integrity.write(integrity);
        self.verifier_config_hash.write(verifier_config_hash);
        self.min_security_bits.write(min_security_bits);
        self.add_new_key_program_hash.write(add_new_key_program_hash);
        self.process_messages_program_hash.write(process_messages_program_hash);
        self.process_deactivate_program_hash.write(process_deactivate_program_hash);
        self.tally_program_hash.write(tally_program_hash);
        self.allowed_program_hashes.write(add_new_key_program_hash, true);
        self.allowed_program_hashes.write(process_messages_program_hash, true);
        self.allowed_program_hashes.write(process_deactivate_program_hash, true);
        self.allowed_program_hashes.write(tally_program_hash, true);
        self.state_commitment.write(initial_state_commitment);
        self.deactivate_commitment.write(initial_deactivate_commitment);
        self.tally_commitment.write(initial_tally_commitment);
        self.keys_added.write(0);
        self.message_batches_processed.write(0);
        self.deactivate_batches_processed.write(0);
        self.total_facts_accepted.write(0);
        self.tally_submitted.write(false);
    }

    #[abi(embed_v0)]
    impl MockAmaciRoundImpl of super::IMockAmaciRound<ContractState> {
        fn set_program_hash_allowed(ref self: ContractState, program_hash: felt252, allowed: bool) {
            assert_admin(@self);
            self.allowed_program_hashes.write(program_hash, allowed);
            self.emit(ProgramHashAllowedSet { program_hash, allowed });
        }

        fn is_program_hash_allowed(self: @ContractState, program_hash: felt252) -> bool {
            self.allowed_program_hashes.read(program_hash)
        }

        fn get_state_commitment(self: @ContractState) -> felt252 {
            self.state_commitment.read()
        }

        fn get_deactivate_commitment(self: @ContractState) -> felt252 {
            self.deactivate_commitment.read()
        }

        fn get_tally_commitment(self: @ContractState) -> felt252 {
            self.tally_commitment.read()
        }

        fn get_keys_added(self: @ContractState) -> felt252 {
            self.keys_added.read()
        }

        fn get_message_batches_processed(self: @ContractState) -> felt252 {
            self.message_batches_processed.read()
        }

        fn get_deactivate_batches_processed(self: @ContractState) -> felt252 {
            self.deactivate_batches_processed.read()
        }

        fn get_total_facts_accepted(self: @ContractState) -> felt252 {
            self.total_facts_accepted.read()
        }

        fn get_tally_submitted(self: @ContractState) -> bool {
            self.tally_submitted.read()
        }

        fn get_expected_fact_hash(
            self: @ContractState, program_hash: felt252, public_output_hash: felt252,
        ) -> felt252 {
            fact_hash(program_hash, public_output_hash)
        }

        fn get_expected_verification_hash(self: @ContractState, fact_hash: felt252) -> felt252 {
            verification_hash(
                fact_hash, self.verifier_config_hash.read(), self.min_security_bits.read(),
            )
        }

        fn submit_operation_fact(
            ref self: ContractState,
            operation_id: felt252,
            program_hash: felt252,
            public_output_hash: felt252,
            fact_hash: felt252,
        ) {
            let verification_hash = validate_fact(
                @self, program_hash, public_output_hash, fact_hash,
            );
            self.total_facts_accepted.write(self.total_facts_accepted.read() + 1);
            self
                .emit(
                    OperationFactAccepted {
                        operation_id,
                        program_hash,
                        public_output_hash,
                        fact_hash,
                        verification_hash,
                    },
                );
        }

        fn submit_add_new_key_fact(
            ref self: ContractState,
            key_nullifier: felt252,
            new_state_commitment: felt252,
            public_output_hash: felt252,
            fact_hash: felt252,
        ) {
            assert(self.used_key_nullifiers.read(key_nullifier) == false, 'KEY_NULLIFIER_USED');
            let verification_hash = validate_fact(
                @self, self.add_new_key_program_hash.read(), public_output_hash, fact_hash,
            );
            self.used_key_nullifiers.write(key_nullifier, true);
            self.state_commitment.write(new_state_commitment);
            self.keys_added.write(self.keys_added.read() + 1);
            self.total_facts_accepted.write(self.total_facts_accepted.read() + 1);
            self
                .emit(
                    AddNewKeyFactAccepted {
                        key_nullifier,
                        new_state_commitment,
                        public_output_hash,
                        fact_hash,
                        verification_hash,
                    },
                );
        }

        fn submit_process_messages_fact(
            ref self: ContractState,
            current_state_commitment: felt252,
            new_state_commitment: felt252,
            current_deactivate_commitment: felt252,
            public_output_hash: felt252,
            fact_hash: felt252,
        ) {
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            assert(
                self.deactivate_commitment.read() == current_deactivate_commitment,
                'DEACT_MISMATCH',
            );
            let verification_hash = validate_fact(
                @self, self.process_messages_program_hash.read(), public_output_hash, fact_hash,
            );
            self.state_commitment.write(new_state_commitment);
            self.message_batches_processed.write(self.message_batches_processed.read() + 1);
            self.total_facts_accepted.write(self.total_facts_accepted.read() + 1);
            self
                .emit(
                    ProcessMessagesFactAccepted {
                        old_state_commitment: current_state_commitment,
                        new_state_commitment,
                        deactivate_commitment: current_deactivate_commitment,
                        public_output_hash,
                        fact_hash,
                        verification_hash,
                    },
                );
        }

        fn submit_process_deactivate_fact(
            ref self: ContractState,
            current_deactivate_commitment: felt252,
            new_deactivate_commitment: felt252,
            current_state_commitment: felt252,
            public_output_hash: felt252,
            fact_hash: felt252,
        ) {
            assert(
                self.deactivate_commitment.read() == current_deactivate_commitment,
                'DEACT_MISMATCH',
            );
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            let verification_hash = validate_fact(
                @self, self.process_deactivate_program_hash.read(), public_output_hash, fact_hash,
            );
            self.deactivate_commitment.write(new_deactivate_commitment);
            self.deactivate_batches_processed.write(self.deactivate_batches_processed.read() + 1);
            self.total_facts_accepted.write(self.total_facts_accepted.read() + 1);
            self
                .emit(
                    ProcessDeactivateFactAccepted {
                        old_deactivate_commitment: current_deactivate_commitment,
                        new_deactivate_commitment,
                        state_commitment: current_state_commitment,
                        public_output_hash,
                        fact_hash,
                        verification_hash,
                    },
                );
        }

        fn submit_tally_fact(
            ref self: ContractState,
            current_tally_commitment: felt252,
            new_tally_commitment: felt252,
            current_state_commitment: felt252,
            public_output_hash: felt252,
            fact_hash: felt252,
        ) {
            assert(self.tally_submitted.read() == false, 'TALLY_ALREADY_DONE');
            assert(self.tally_commitment.read() == current_tally_commitment, 'TALLY_MISMATCH');
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            let verification_hash = validate_fact(
                @self, self.tally_program_hash.read(), public_output_hash, fact_hash,
            );
            self.tally_commitment.write(new_tally_commitment);
            self.tally_submitted.write(true);
            self.total_facts_accepted.write(self.total_facts_accepted.read() + 1);
            self
                .emit(
                    TallyFactAccepted {
                        old_tally_commitment: current_tally_commitment,
                        new_tally_commitment,
                        state_commitment: current_state_commitment,
                        public_output_hash,
                        fact_hash,
                        verification_hash,
                    },
                );
        }
    }

    fn validate_fact(
        self: @ContractState,
        program_hash: felt252,
        public_output_hash: felt252,
        provided_fact_hash: felt252,
    ) -> felt252 {
        assert(self.allowed_program_hashes.read(program_hash), 'PROGRAM_NOT_ALLOWED');
        let expected_fact_hash = fact_hash(program_hash, public_output_hash);
        assert(provided_fact_hash == expected_fact_hash, 'FACT_BINDING_MISMATCH');

        let verifier_config_hash = self.verifier_config_hash.read();
        let min_security_bits = self.min_security_bits.read();
        let expected_verification_hash = verification_hash(
            provided_fact_hash, verifier_config_hash, min_security_bits,
        );
        let integrity = IIntegrityDispatcher { contract_address: self.integrity.read() };
        let valid = if verifier_config_hash == 0 {
            integrity.is_fact_hash_valid_with_security(provided_fact_hash, min_security_bits)
        } else {
            integrity.is_verification_hash_valid(expected_verification_hash)
        };
        assert(valid, 'INVALID_INTEGRITY_FACT');
        expected_verification_hash
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'ONLY_ADMIN');
    }

    fn fact_hash(program_hash: felt252, public_output_hash: felt252) -> felt252 {
        poseidon_pair_hash(program_hash, public_output_hash)
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
        use super::{fact_hash, verification_hash};

        #[test]
        fn fact_hash_matches_tally_wrapper_pair_hash_vector() {
            assert(
                fact_hash(
                    0x1234, 0x456,
                ) == 0x34bdae18917a12eef4020013ee2b4f8f164632685a887bdfa5eb67a22962b5d,
                'FACT_HASH_VECTOR_BAD',
            );
        }

        #[test]
        fn verification_hash_matches_starknet_js_vector() {
            assert(
                verification_hash(
                    0x1234, 0x5678, 80,
                ) == 0x57458c3f7260103b710ff2509a3de1f5ac2a2a8fd9604578aaf4865faff08d9,
                'VERIFY_HASH_VECTOR_BAD',
            );
        }
    }
}
