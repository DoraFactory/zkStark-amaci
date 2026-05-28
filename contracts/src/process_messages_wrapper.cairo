#[starknet::interface]
pub trait IProcessMessagesStarkWrapper<TContractState> {
    fn get_state_commitment(self: @TContractState) -> felt252;
    fn get_deactivate_commitment(self: @TContractState) -> felt252;
    fn get_message_batches_processed(self: @TContractState) -> felt252;
    fn get_expected_plain_fact_hash(self: @TContractState, public_output_hash: felt252) -> felt252;
    fn get_expected_atlantic_metadata_fact_hash(
        self: @TContractState, metadata_program_hash: felt252, metadata_output: Span<felt252>,
    ) -> felt252;
    fn get_expected_verification_hash(self: @TContractState, fact_hash: felt252) -> felt252;
    fn submit_process_messages_fact(
        ref self: TContractState,
        current_state_commitment: felt252,
        new_state_commitment: felt252,
        current_deactivate_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
    );
    fn submit_process_messages_atlantic_metadata_fact(
        ref self: TContractState,
        current_state_commitment: felt252,
        new_state_commitment: felt252,
        current_deactivate_commitment: felt252,
        metadata_program_hash: felt252,
        metadata_output: Span<felt252>,
        fact_hash: felt252,
    );
}

#[starknet::contract]
pub mod ProcessMessagesStarkWrapper {
    use core::hash::HashStateTrait;
    use core::poseidon::PoseidonTrait;
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use crate::integrity_fact_registry::{
        is_fact_hash_valid_with_security, is_verification_hash_valid,
    };

    const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b; // MACISTARK
    const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
    const PROCESS_MESSAGES_NATIVE_CIRCUIT_ID: felt252 =
        0x414d4143495f50524f434553535f4d53475f4e4154495645; // AMACI_PROCESS_MSG_NATIVE
    const STARKNET_POSEIDON_HASH_SCHEME: felt252 =
        0x535441524b4e45545f504f534549444f4e; // STARKNET_POSEIDON
    const SHARP_BOOTLOADER_PROGRAM_HASH: felt252 =
        0x5ab580b04e3532b6b18f81cfa654a05e29dd8e2352d88df1e765a84072db07;
    const PROCESS_MESSAGES_NATIVE_OUTPUT_LEN: usize = 16;

    #[storage]
    struct Storage {
        integrity: ContractAddress,
        fact_registry_mode: felt252,
        is_fact_mocked: bool,
        verifier_config_hash: felt252,
        min_security_bits: u32,
        process_messages_program_hash: felt252,
        state_commitment: felt252,
        deactivate_commitment: felt252,
        message_batches_processed: felt252,
        total_facts_accepted: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ProcessMessagesFactAccepted: ProcessMessagesFactAccepted,
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

    #[constructor]
    fn constructor(
        ref self: ContractState,
        integrity: ContractAddress,
        fact_registry_mode: felt252,
        is_fact_mocked: bool,
        verifier_config_hash: felt252,
        min_security_bits: u32,
        process_messages_program_hash: felt252,
        initial_state_commitment: felt252,
        initial_deactivate_commitment: felt252,
    ) {
        self.integrity.write(integrity);
        self.fact_registry_mode.write(fact_registry_mode);
        self.is_fact_mocked.write(is_fact_mocked);
        self.verifier_config_hash.write(verifier_config_hash);
        self.min_security_bits.write(min_security_bits);
        self.process_messages_program_hash.write(process_messages_program_hash);
        self.state_commitment.write(initial_state_commitment);
        self.deactivate_commitment.write(initial_deactivate_commitment);
        self.message_batches_processed.write(0);
        self.total_facts_accepted.write(0);
    }

    #[abi(embed_v0)]
    impl ProcessMessagesStarkWrapperImpl of super::IProcessMessagesStarkWrapper<ContractState> {
        fn get_state_commitment(self: @ContractState) -> felt252 {
            self.state_commitment.read()
        }

        fn get_deactivate_commitment(self: @ContractState) -> felt252 {
            self.deactivate_commitment.read()
        }

        fn get_message_batches_processed(self: @ContractState) -> felt252 {
            self.message_batches_processed.read()
        }

        fn get_expected_plain_fact_hash(
            self: @ContractState, public_output_hash: felt252,
        ) -> felt252 {
            fact_hash(self.process_messages_program_hash.read(), public_output_hash)
        }

        fn get_expected_atlantic_metadata_fact_hash(
            self: @ContractState, metadata_program_hash: felt252, metadata_output: Span<felt252>,
        ) -> felt252 {
            bootloaded_fact_hash_for_output(
                SHARP_BOOTLOADER_PROGRAM_HASH, metadata_program_hash, metadata_output,
            )
        }

        fn get_expected_verification_hash(self: @ContractState, fact_hash: felt252) -> felt252 {
            verification_hash(
                fact_hash, self.verifier_config_hash.read(), self.min_security_bits.read(),
            )
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
            let verification_hash = validate_plain_fact(@self, public_output_hash, fact_hash);
            accept_process_messages_fact(
                ref self,
                current_state_commitment,
                new_state_commitment,
                current_deactivate_commitment,
                public_output_hash,
                fact_hash,
                verification_hash,
            );
        }

        fn submit_process_messages_atlantic_metadata_fact(
            ref self: ContractState,
            current_state_commitment: felt252,
            new_state_commitment: felt252,
            current_deactivate_commitment: felt252,
            metadata_program_hash: felt252,
            metadata_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            assert(
                self.deactivate_commitment.read() == current_deactivate_commitment,
                'DEACT_MISMATCH',
            );
            let verification_hash = validate_atlantic_metadata_fact(
                @self, metadata_program_hash, metadata_output, fact_hash,
            );
            let output_start = find_native_output_start(
                metadata_output,
                PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
                PROCESS_MESSAGES_NATIVE_OUTPUT_LEN,
            );
            assert_native_output_header_at(
                metadata_output, output_start, PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
            );
            assert(
                *metadata_output.at(output_start + 11) == current_state_commitment,
                'STATE_CURRENT_BAD',
            );
            assert(*metadata_output.at(output_start + 12) == new_state_commitment, 'STATE_NEW_BAD');
            assert(
                *metadata_output.at(output_start + 13) == current_deactivate_commitment,
                'DEACT_OUTPUT_BAD',
            );
            let public_output_hash = poseidon_hash_output_at(
                metadata_output, output_start, PROCESS_MESSAGES_NATIVE_OUTPUT_LEN,
            );
            accept_process_messages_fact(
                ref self,
                current_state_commitment,
                new_state_commitment,
                current_deactivate_commitment,
                public_output_hash,
                fact_hash,
                verification_hash,
            );
        }
    }

    fn validate_plain_fact(
        self: @ContractState, public_output_hash: felt252, provided_fact_hash: felt252,
    ) -> felt252 {
        let expected_fact_hash = fact_hash(
            self.process_messages_program_hash.read(), public_output_hash,
        );
        assert(provided_fact_hash == expected_fact_hash, 'FACT_BINDING_MISMATCH');
        validate_registered_fact(self, provided_fact_hash)
    }

    fn validate_atlantic_metadata_fact(
        self: @ContractState,
        metadata_program_hash: felt252,
        metadata_output: Span<felt252>,
        provided_fact_hash: felt252,
    ) -> felt252 {
        assert(metadata_output.len() > 4, 'METADATA_OUTPUT_SHORT');
        assert(
            *metadata_output.at(4) == self.process_messages_program_hash.read(), 'PROGRAM_MISMATCH',
        );
        let expected_fact_hash = bootloaded_fact_hash_for_output(
            SHARP_BOOTLOADER_PROGRAM_HASH, metadata_program_hash, metadata_output,
        );
        assert(provided_fact_hash == expected_fact_hash, 'FACT_BINDING_MISMATCH');
        validate_registered_fact(self, provided_fact_hash)
    }

    fn validate_registered_fact(self: @ContractState, provided_fact_hash: felt252) -> felt252 {
        let verifier_config_hash = self.verifier_config_hash.read();
        let min_security_bits = self.min_security_bits.read();
        let expected_verification_hash = verification_hash(
            provided_fact_hash, verifier_config_hash, min_security_bits,
        );
        let valid = if verifier_config_hash == 0 {
            is_fact_hash_valid_with_security(
                self.integrity.read(),
                self.fact_registry_mode.read(),
                self.is_fact_mocked.read(),
                provided_fact_hash,
                min_security_bits,
            )
        } else {
            is_verification_hash_valid(
                self.integrity.read(),
                self.fact_registry_mode.read(),
                self.is_fact_mocked.read(),
                expected_verification_hash,
            )
        };
        assert(valid, 'INVALID_INTEGRITY_FACT');
        expected_verification_hash
    }

    fn accept_process_messages_fact(
        ref self: ContractState,
        current_state_commitment: felt252,
        new_state_commitment: felt252,
        current_deactivate_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
        verification_hash: felt252,
    ) {
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

    fn bootloaded_fact_hash_for_output(
        bootloader_program_hash: felt252, child_program_hash: felt252, child_output: Span<felt252>,
    ) -> felt252 {
        let bootloader_output_hash = bootloader_output_hash(child_program_hash, child_output);
        poseidon_pair_hash(bootloader_program_hash, bootloader_output_hash)
    }

    fn bootloader_output_hash(child_program_hash: felt252, child_output: Span<felt252>) -> felt252 {
        let mut output_hash = PoseidonTrait::new()
            .update(1)
            .update(child_output.len().into() + 2)
            .update(child_program_hash);
        for x in child_output {
            output_hash = output_hash.update(*x);
        }
        output_hash.finalize()
    }

    fn find_native_output_start(
        metadata_output: Span<felt252>, circuit_id: felt252, output_len: usize,
    ) -> usize {
        assert(metadata_output.len() >= output_len, 'METADATA_OUTPUT_SHORT');
        let limit = metadata_output.len() - output_len + 1;
        let mut found = false;
        let mut found_start: usize = 0;
        let mut i: usize = 0;
        while i < limit {
            if *metadata_output.at(i) == PUBLIC_OUTPUT_MAGIC {
                if *metadata_output.at(i + 1) == NATIVE_PUBLIC_OUTPUT_VERSION {
                    if *metadata_output.at(i + 2) == circuit_id {
                        found = true;
                        found_start = i;
                        i = limit;
                    } else {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        assert(found, 'NATIVE_OUTPUT_MISSING');
        found_start
    }

    fn assert_native_output_header_at(
        metadata_output: Span<felt252>, start: usize, circuit_id: felt252,
    ) {
        assert(*metadata_output.at(start) == PUBLIC_OUTPUT_MAGIC, 'NATIVE_MAGIC_BAD');
        assert(
            *metadata_output.at(start + 1) == NATIVE_PUBLIC_OUTPUT_VERSION, 'NATIVE_VERSION_BAD',
        );
        assert(*metadata_output.at(start + 2) == circuit_id, 'NATIVE_CIRCUIT_BAD');
        assert(*metadata_output.at(start + 3) == STARKNET_POSEIDON_HASH_SCHEME, 'NATIVE_HASH_BAD');
    }

    fn poseidon_hash_output_at(output: Span<felt252>, start: usize, len: usize) -> felt252 {
        let mut output_hash = PoseidonTrait::new();
        let mut i: usize = 0;
        while i < len {
            output_hash = output_hash.update(*output.at(start + i));
            i += 1;
        }
        output_hash.finalize()
    }

    fn fact_hash(program_hash: felt252, public_output_hash: felt252) -> felt252 {
        poseidon_pair_hash(program_hash, public_output_hash)
    }

    fn poseidon_pair_hash(left: felt252, right: felt252) -> felt252 {
        PoseidonTrait::new().update(left).update(right).finalize()
    }

    fn verification_hash(
        fact_hash: felt252, verifier_config_hash: felt252, security_bits: u32,
    ) -> felt252 {
        PoseidonTrait::new()
            .update(fact_hash)
            .update(verifier_config_hash)
            .update(security_bits.into())
            .finalize()
    }
}
