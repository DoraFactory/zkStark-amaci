#[starknet::interface]
pub trait IMockAmaciRound<TContractState> {
    fn set_program_hash_allowed(ref self: TContractState, program_hash: felt252, allowed: bool);
    fn is_program_hash_allowed(self: @TContractState, program_hash: felt252) -> bool;
    fn get_state_commitment(self: @TContractState) -> felt252;
    fn get_deactivate_commitment(self: @TContractState) -> felt252;
    fn get_deactivate_root(self: @TContractState) -> felt252;
    fn get_tally_commitment(self: @TContractState) -> felt252;
    fn get_num_signups(self: @TContractState) -> u32;
    fn get_message_chain_length(self: @TContractState) -> u32;
    fn get_deactivate_message_chain_length(self: @TContractState) -> u32;
    fn get_processed_message_count(self: @TContractState) -> u32;
    fn get_processed_deactivate_message_count(self: @TContractState) -> u32;
    fn get_message_hash(self: @TContractState, index: u32) -> felt252;
    fn get_deactivate_message_hash(self: @TContractState, index: u32) -> felt252;
    fn get_keys_added(self: @TContractState) -> felt252;
    fn get_message_batches_processed(self: @TContractState) -> felt252;
    fn get_deactivate_batches_processed(self: @TContractState) -> felt252;
    fn get_total_facts_accepted(self: @TContractState) -> felt252;
    fn get_tally_submitted(self: @TContractState) -> bool;
    fn get_expected_fact_hash(
        self: @TContractState, program_hash: felt252, public_output_hash: felt252,
    ) -> felt252;
    fn get_expected_plain_fact_hash_for_output(
        self: @TContractState, program_hash: felt252, public_output: Span<felt252>,
    ) -> felt252;
    fn get_expected_bootloaded_fact_hash_for_output(
        self: @TContractState,
        bootloader_program_hash: felt252,
        child_program_hash: felt252,
        child_output: Span<felt252>,
    ) -> felt252;
    fn get_expected_wrapped_bootloaded_fact_hash_for_output(
        self: @TContractState,
        wrapper_program_hash: felt252,
        bootloader_program_hash: felt252,
        child_program_hash: felt252,
        child_output: Span<felt252>,
    ) -> felt252;
    fn get_expected_verification_hash(self: @TContractState, fact_hash: felt252) -> felt252;
    fn submit_operation_fact(
        ref self: TContractState,
        operation_id: felt252,
        program_hash: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
    );
    fn sign_up(
        ref self: TContractState,
        pub_key_x: felt252,
        pub_key_y: felt252,
        voice_credit_balance: felt252,
    );
    fn publish_deactivate_message(
        ref self: TContractState,
        message: Span<felt252>,
        enc_pub_key_x: felt252,
        enc_pub_key_y: felt252,
    );
    fn publish_message(
        ref self: TContractState,
        message: Span<felt252>,
        enc_pub_key_x: felt252,
        enc_pub_key_y: felt252,
    );
    fn submit_add_new_key_fact(
        ref self: TContractState,
        key_nullifier: felt252,
        new_state_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
    );
    fn submit_add_new_key_atlantic_metadata_fact(
        ref self: TContractState,
        key_nullifier: felt252,
        new_state_commitment: felt252,
        metadata_program_hash: felt252,
        metadata_output: Span<felt252>,
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
    fn submit_process_messages_atlantic_metadata_fact(
        ref self: TContractState,
        current_state_commitment: felt252,
        new_state_commitment: felt252,
        current_deactivate_commitment: felt252,
        metadata_program_hash: felt252,
        metadata_output: Span<felt252>,
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
    fn submit_process_deactivate_atlantic_metadata_fact(
        ref self: TContractState,
        current_deactivate_commitment: felt252,
        new_deactivate_commitment: felt252,
        current_state_commitment: felt252,
        metadata_program_hash: felt252,
        metadata_output: Span<felt252>,
        fact_hash: felt252,
    );
    fn submit_operation_atlantic_metadata_fact(
        ref self: TContractState,
        operation_id: felt252,
        child_program_hash: felt252,
        metadata_program_hash: felt252,
        metadata_output: Span<felt252>,
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
    fn submit_tally_plain_output_fact(
        ref self: TContractState,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
        current_state_commitment: felt252,
        child_output: Span<felt252>,
        fact_hash: felt252,
    );
    fn submit_tally_bootloaded_output_fact(
        ref self: TContractState,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
        current_state_commitment: felt252,
        bootloader_program_hash: felt252,
        child_output: Span<felt252>,
        fact_hash: felt252,
    );
    fn submit_tally_wrapped_bootloaded_output_fact(
        ref self: TContractState,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
        current_state_commitment: felt252,
        wrapper_program_hash: felt252,
        bootloader_program_hash: felt252,
        child_output: Span<felt252>,
        fact_hash: felt252,
    );
    fn submit_tally_atlantic_metadata_fact(
        ref self: TContractState,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
        current_state_commitment: felt252,
        metadata_program_hash: felt252,
        metadata_output: Span<felt252>,
        fact_hash: felt252,
    );
}

#[starknet::contract]
pub mod MockAmaciRound {
    use core::hash::HashStateTrait;
    use core::poseidon::PoseidonTrait;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use crate::integrity_fact_registry::{
        is_fact_hash_valid_with_security, is_verification_hash_valid,
    };

    const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b; // MACISTARK
    const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
    const TALLY_VOTES_NATIVE_CIRCUIT_ID: felt252 =
        0x414d4143495f54414c4c595f4e4154495645; // AMACI_TALLY_NATIVE
    const ADD_NEW_KEY_NATIVE_CIRCUIT_ID: felt252 =
        0x414d4143495f4144445f4b45595f4e4154495645; // AMACI_ADD_KEY_NATIVE
    const PROCESS_MESSAGES_NATIVE_CIRCUIT_ID: felt252 =
        0x414d4143495f50524f434553535f4d53475f4e4154495645; // AMACI_PROCESS_MSG_NATIVE
    const PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID: felt252 =
        0x414d4143495f50524f434553535f44454143545f4e4154495645; // AMACI_PROCESS_DEACT_NATIVE
    const STARKNET_POSEIDON_HASH_SCHEME: felt252 =
        0x535441524b4e45545f504f534549444f4e; // STARKNET_POSEIDON
    const SHARP_BOOTLOADER_PROGRAM_HASH: felt252 =
        0x5ab580b04e3532b6b18f81cfa654a05e29dd8e2352d88df1e765a84072db07;
    const TALLY_NATIVE_OUTPUT_LEN: usize = 12;
    const ADD_NEW_KEY_NATIVE_OUTPUT_LEN: usize = 19;
    const PROCESS_MESSAGES_NATIVE_OUTPUT_LEN: usize = 16;
    const PROCESS_DEACTIVATE_NATIVE_OUTPUT_LEN: usize = 16;
    const MESSAGE_BATCH_SIZE: u32 = 3;
    const MAX_SIGNUPS: u32 = 25;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        integrity: ContractAddress,
        fact_registry_mode: felt252,
        is_fact_mocked: bool,
        verifier_config_hash: felt252,
        min_security_bits: u32,
        add_new_key_program_hash: felt252,
        process_messages_program_hash: felt252,
        process_deactivate_program_hash: felt252,
        tally_program_hash: felt252,
        allowed_program_hashes: Map<felt252, bool>,
        used_key_nullifiers: Map<felt252, bool>,
        registered_pub_keys: Map<felt252, bool>,
        used_enc_pub_keys: Map<felt252, bool>,
        used_deactivate_enc_pub_keys: Map<felt252, bool>,
        state_commitment: felt252,
        deactivate_root: felt252,
        deactivate_commitment: felt252,
        tally_commitment: felt252,
        num_signups: u32,
        message_hashes: Map<u32, felt252>,
        deactivate_message_hashes: Map<u32, felt252>,
        message_chain_length: u32,
        deactivate_message_chain_length: u32,
        processed_message_count: u32,
        processed_deactivate_message_count: u32,
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
        SignUp: SignUp,
        MessagePublished: MessagePublished,
        DeactivateMessagePublished: DeactivateMessagePublished,
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
    struct SignUp {
        pub_key_hash: felt252,
        state_index: u32,
        voice_credit_balance: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct MessagePublished {
        chain_index: u32,
        message_hash: felt252,
        enc_pub_key_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct DeactivateMessagePublished {
        chain_index: u32,
        message_hash: felt252,
        enc_pub_key_hash: felt252,
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
        fact_registry_mode: felt252,
        is_fact_mocked: bool,
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
        self.fact_registry_mode.write(fact_registry_mode);
        self.is_fact_mocked.write(is_fact_mocked);
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
        self.deactivate_root.write(0);
        self.deactivate_commitment.write(initial_deactivate_commitment);
        self.tally_commitment.write(initial_tally_commitment);
        self.num_signups.write(0);
        self.message_hashes.write(0, 0);
        self.deactivate_message_hashes.write(0, 0);
        self.message_chain_length.write(0);
        self.deactivate_message_chain_length.write(0);
        self.processed_message_count.write(0);
        self.processed_deactivate_message_count.write(0);
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

        fn get_deactivate_root(self: @ContractState) -> felt252 {
            self.deactivate_root.read()
        }

        fn get_tally_commitment(self: @ContractState) -> felt252 {
            self.tally_commitment.read()
        }

        fn get_num_signups(self: @ContractState) -> u32 {
            self.num_signups.read()
        }

        fn get_message_chain_length(self: @ContractState) -> u32 {
            self.message_chain_length.read()
        }

        fn get_deactivate_message_chain_length(self: @ContractState) -> u32 {
            self.deactivate_message_chain_length.read()
        }

        fn get_processed_message_count(self: @ContractState) -> u32 {
            self.processed_message_count.read()
        }

        fn get_processed_deactivate_message_count(self: @ContractState) -> u32 {
            self.processed_deactivate_message_count.read()
        }

        fn get_message_hash(self: @ContractState, index: u32) -> felt252 {
            self.message_hashes.read(index)
        }

        fn get_deactivate_message_hash(self: @ContractState, index: u32) -> felt252 {
            self.deactivate_message_hashes.read(index)
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

        fn get_expected_plain_fact_hash_for_output(
            self: @ContractState, program_hash: felt252, public_output: Span<felt252>,
        ) -> felt252 {
            plain_fact_hash_for_output(program_hash, public_output)
        }

        fn get_expected_bootloaded_fact_hash_for_output(
            self: @ContractState,
            bootloader_program_hash: felt252,
            child_program_hash: felt252,
            child_output: Span<felt252>,
        ) -> felt252 {
            bootloaded_fact_hash_for_output(
                bootloader_program_hash, child_program_hash, child_output,
            )
        }

        fn get_expected_wrapped_bootloaded_fact_hash_for_output(
            self: @ContractState,
            wrapper_program_hash: felt252,
            bootloader_program_hash: felt252,
            child_program_hash: felt252,
            child_output: Span<felt252>,
        ) -> felt252 {
            wrapped_bootloaded_fact_hash_for_output(
                wrapper_program_hash, bootloader_program_hash, child_program_hash, child_output,
            )
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

        fn sign_up(
            ref self: ContractState,
            pub_key_x: felt252,
            pub_key_y: felt252,
            voice_credit_balance: felt252,
        ) {
            assert_can_sign_up(@self);
            assert(voice_credit_balance != 0, 'VC_ZERO');
            let pub_key_hash = poseidon_pair_hash(pub_key_x, pub_key_y);
            assert(pub_key_hash != 0, 'PUB_KEY_ZERO');
            assert(self.registered_pub_keys.read(pub_key_hash) == false, 'PUB_KEY_REGISTERED');
            let state_index = self.num_signups.read();
            assert(state_index < MAX_SIGNUPS, 'STATE_TREE_FULL');
            self.registered_pub_keys.write(pub_key_hash, true);
            self.num_signups.write(state_index + 1);
            self.emit(SignUp { pub_key_hash, state_index, voice_credit_balance });
        }

        fn publish_deactivate_message(
            ref self: ContractState,
            message: Span<felt252>,
            enc_pub_key_x: felt252,
            enc_pub_key_y: felt252,
        ) {
            assert_can_publish_deactivate(@self);
            append_message(ref self, message, enc_pub_key_x, enc_pub_key_y, true);
        }

        fn publish_message(
            ref self: ContractState,
            message: Span<felt252>,
            enc_pub_key_x: felt252,
            enc_pub_key_y: felt252,
        ) {
            assert_can_publish_vote(@self);
            append_message(ref self, message, enc_pub_key_x, enc_pub_key_y, false);
        }

        fn submit_add_new_key_fact(
            ref self: ContractState,
            key_nullifier: felt252,
            new_state_commitment: felt252,
            public_output_hash: felt252,
            fact_hash: felt252,
        ) {
            assert_can_add_new_key(@self);
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

        fn submit_add_new_key_atlantic_metadata_fact(
            ref self: ContractState,
            key_nullifier: felt252,
            new_state_commitment: felt252,
            metadata_program_hash: felt252,
            metadata_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            assert_can_add_new_key(@self);
            assert(self.used_key_nullifiers.read(key_nullifier) == false, 'KEY_NULLIFIER_USED');
            let verification_hash = validate_atlantic_metadata_fact(
                @self,
                self.add_new_key_program_hash.read(),
                metadata_program_hash,
                metadata_output,
                fact_hash,
            );
            let output_start = find_native_output_start(
                metadata_output, ADD_NEW_KEY_NATIVE_CIRCUIT_ID, ADD_NEW_KEY_NATIVE_OUTPUT_LEN,
            );
            assert_native_output_header_at(
                metadata_output, output_start, ADD_NEW_KEY_NATIVE_CIRCUIT_ID,
            );
            assert(
                *metadata_output.at(output_start + 6) == self.deactivate_root.read(),
                'DEACT_ROOT_BAD',
            );
            assert(*metadata_output.at(output_start + 8) == key_nullifier, 'KEY_NULLIFIER_BAD');
            let public_output_hash = poseidon_hash_output_at(
                metadata_output, output_start, ADD_NEW_KEY_NATIVE_OUTPUT_LEN,
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
            assert_can_process_messages(@self);
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            assert(
                self.deactivate_commitment.read() == current_deactivate_commitment,
                'DEACT_MISMATCH',
            );
            let verification_hash = validate_fact(
                @self, self.process_messages_program_hash.read(), public_output_hash, fact_hash,
            );
            self.state_commitment.write(new_state_commitment);
            self.processed_message_count.write(self.message_chain_length.read());
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

        fn submit_process_messages_atlantic_metadata_fact(
            ref self: ContractState,
            current_state_commitment: felt252,
            new_state_commitment: felt252,
            current_deactivate_commitment: felt252,
            metadata_program_hash: felt252,
            metadata_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            assert_can_process_messages(@self);
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            assert(
                self.deactivate_commitment.read() == current_deactivate_commitment,
                'DEACT_MISMATCH',
            );
            let verification_hash = validate_atlantic_metadata_fact(
                @self,
                self.process_messages_program_hash.read(),
                metadata_program_hash,
                metadata_output,
                fact_hash,
            );
            let output_start = find_native_output_start(
                metadata_output,
                PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
                PROCESS_MESSAGES_NATIVE_OUTPUT_LEN,
            );
            let (batch_start, batch_end) = current_message_batch(@self);
            assert_native_output_header_at(
                metadata_output, output_start, PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
            );
            assert(
                *metadata_output.at(output_start + 9) == self.message_hashes.read(batch_start),
                'MSG_START_BAD',
            );
            assert(
                *metadata_output.at(output_start + 10) == self.message_hashes.read(batch_end),
                'MSG_END_BAD',
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
            self.state_commitment.write(new_state_commitment);
            self.processed_message_count.write(batch_end);
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
            assert_can_process_deactivate(@self);
            assert(
                self.deactivate_commitment.read() == current_deactivate_commitment,
                'DEACT_MISMATCH',
            );
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            let verification_hash = validate_fact(
                @self, self.process_deactivate_program_hash.read(), public_output_hash, fact_hash,
            );
            self.deactivate_commitment.write(new_deactivate_commitment);
            self
                .processed_deactivate_message_count
                .write(self.deactivate_message_chain_length.read());
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

        fn submit_process_deactivate_atlantic_metadata_fact(
            ref self: ContractState,
            current_deactivate_commitment: felt252,
            new_deactivate_commitment: felt252,
            current_state_commitment: felt252,
            metadata_program_hash: felt252,
            metadata_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            assert_can_process_deactivate(@self);
            assert(
                self.deactivate_commitment.read() == current_deactivate_commitment,
                'DEACT_MISMATCH',
            );
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            let verification_hash = validate_atlantic_metadata_fact(
                @self,
                self.process_deactivate_program_hash.read(),
                metadata_program_hash,
                metadata_output,
                fact_hash,
            );
            let output_start = find_native_output_start(
                metadata_output,
                PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID,
                PROCESS_DEACTIVATE_NATIVE_OUTPUT_LEN,
            );
            let (batch_start, batch_end) = current_deactivate_batch(@self);
            assert_native_output_header_at(
                metadata_output, output_start, PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID,
            );
            assert(
                *metadata_output
                    .at(output_start + 9) == self
                    .deactivate_message_hashes
                    .read(batch_start),
                'DMSG_START_BAD',
            );
            assert(
                *metadata_output
                    .at(output_start + 10) == self
                    .deactivate_message_hashes
                    .read(batch_end),
                'DMSG_END_BAD',
            );
            assert(
                *metadata_output.at(output_start + 11) == current_deactivate_commitment,
                'DEACT_CURRENT_BAD',
            );
            assert(
                *metadata_output.at(output_start + 12) == new_deactivate_commitment,
                'DEACT_NEW_BAD',
            );
            let public_output_hash = poseidon_hash_output_at(
                metadata_output, output_start, PROCESS_DEACTIVATE_NATIVE_OUTPUT_LEN,
            );
            let new_deactivate_root = *metadata_output.at(output_start + 7);
            self.deactivate_root.write(new_deactivate_root);
            self.deactivate_commitment.write(new_deactivate_commitment);
            self.processed_deactivate_message_count.write(batch_end);
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

        fn submit_operation_atlantic_metadata_fact(
            ref self: ContractState,
            operation_id: felt252,
            child_program_hash: felt252,
            metadata_program_hash: felt252,
            metadata_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            let verification_hash = validate_atlantic_metadata_fact(
                @self, child_program_hash, metadata_program_hash, metadata_output, fact_hash,
            );
            let public_output_hash = poseidon_hash_output(metadata_output);
            self.total_facts_accepted.write(self.total_facts_accepted.read() + 1);
            self
                .emit(
                    OperationFactAccepted {
                        operation_id,
                        program_hash: child_program_hash,
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
            assert_can_tally(@self);
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

        fn submit_tally_plain_output_fact(
            ref self: ContractState,
            current_tally_commitment: felt252,
            new_tally_commitment: felt252,
            current_state_commitment: felt252,
            child_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            assert_can_tally(@self);
            assert(self.tally_commitment.read() == current_tally_commitment, 'TALLY_MISMATCH');
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            let expected_fact_hash = plain_fact_hash_for_output(
                self.tally_program_hash.read(), child_output,
            );
            assert(fact_hash == expected_fact_hash, 'FACT_BINDING_MISMATCH');
            let verification_hash = validate_registered_fact(@self, fact_hash);
            accept_tally_fact(
                ref self,
                current_tally_commitment,
                new_tally_commitment,
                current_state_commitment,
                0,
                fact_hash,
                verification_hash,
            );
        }

        fn submit_tally_bootloaded_output_fact(
            ref self: ContractState,
            current_tally_commitment: felt252,
            new_tally_commitment: felt252,
            current_state_commitment: felt252,
            bootloader_program_hash: felt252,
            child_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            assert_can_tally(@self);
            assert(self.tally_commitment.read() == current_tally_commitment, 'TALLY_MISMATCH');
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            let expected_fact_hash = bootloaded_fact_hash_for_output(
                bootloader_program_hash, self.tally_program_hash.read(), child_output,
            );
            assert(fact_hash == expected_fact_hash, 'FACT_BINDING_MISMATCH');
            let verification_hash = validate_registered_fact(@self, fact_hash);
            accept_tally_fact(
                ref self,
                current_tally_commitment,
                new_tally_commitment,
                current_state_commitment,
                0,
                fact_hash,
                verification_hash,
            );
        }

        fn submit_tally_wrapped_bootloaded_output_fact(
            ref self: ContractState,
            current_tally_commitment: felt252,
            new_tally_commitment: felt252,
            current_state_commitment: felt252,
            wrapper_program_hash: felt252,
            bootloader_program_hash: felt252,
            child_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            assert_can_tally(@self);
            assert(self.tally_commitment.read() == current_tally_commitment, 'TALLY_MISMATCH');
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            let expected_fact_hash = wrapped_bootloaded_fact_hash_for_output(
                wrapper_program_hash,
                bootloader_program_hash,
                self.tally_program_hash.read(),
                child_output,
            );
            assert(fact_hash == expected_fact_hash, 'FACT_BINDING_MISMATCH');
            let verification_hash = validate_registered_fact(@self, fact_hash);
            accept_tally_fact(
                ref self,
                current_tally_commitment,
                new_tally_commitment,
                current_state_commitment,
                0,
                fact_hash,
                verification_hash,
            );
        }

        fn submit_tally_atlantic_metadata_fact(
            ref self: ContractState,
            current_tally_commitment: felt252,
            new_tally_commitment: felt252,
            current_state_commitment: felt252,
            metadata_program_hash: felt252,
            metadata_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            assert_can_tally(@self);
            assert(self.tally_commitment.read() == current_tally_commitment, 'TALLY_MISMATCH');
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            assert(metadata_output.len() > 4, 'METADATA_OUTPUT_SHORT');
            assert(
                *metadata_output.at(4) == self.tally_program_hash.read(), 'TALLY_PROGRAM_MISMATCH',
            );

            let tally_output_start = find_native_tally_output_start(metadata_output);
            assert_native_tally_output_at(
                metadata_output,
                tally_output_start,
                current_state_commitment,
                current_tally_commitment,
                new_tally_commitment,
            );

            let expected_fact_hash = bootloaded_fact_hash_for_output(
                SHARP_BOOTLOADER_PROGRAM_HASH, metadata_program_hash, metadata_output,
            );
            assert(fact_hash == expected_fact_hash, 'FACT_BINDING_MISMATCH');
            let verification_hash = validate_registered_fact(@self, fact_hash);
            let public_output_hash = poseidon_hash_output_at(
                metadata_output, tally_output_start, TALLY_NATIVE_OUTPUT_LEN,
            );
            accept_tally_fact(
                ref self,
                current_tally_commitment,
                new_tally_commitment,
                current_state_commitment,
                public_output_hash,
                fact_hash,
                verification_hash,
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

    fn validate_atlantic_metadata_fact(
        self: @ContractState,
        child_program_hash: felt252,
        metadata_program_hash: felt252,
        metadata_output: Span<felt252>,
        provided_fact_hash: felt252,
    ) -> felt252 {
        assert(self.allowed_program_hashes.read(child_program_hash), 'PROGRAM_NOT_ALLOWED');
        assert(metadata_output.len() > 4, 'METADATA_OUTPUT_SHORT');
        assert(*metadata_output.at(4) == child_program_hash, 'PROGRAM_MISMATCH');
        let expected_fact_hash = bootloaded_fact_hash_for_output(
            SHARP_BOOTLOADER_PROGRAM_HASH, metadata_program_hash, metadata_output,
        );
        assert(provided_fact_hash == expected_fact_hash, 'FACT_BINDING_MISMATCH');
        validate_registered_fact(self, provided_fact_hash)
    }

    fn accept_tally_fact(
        ref self: ContractState,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
        current_state_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
        verification_hash: felt252,
    ) {
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

    fn assert_can_sign_up(self: @ContractState) {
        assert(self.tally_submitted.read() == false, 'TALLY_ALREADY_DONE');
        assert(self.deactivate_message_chain_length.read() == 0, 'DEACT_STARTED');
        assert(self.keys_added.read() == 0, 'KEYS_ALREADY_ADDED');
        assert(self.message_chain_length.read() == 0, 'MSG_STARTED');
    }

    fn assert_can_publish_deactivate(self: @ContractState) {
        assert(self.tally_submitted.read() == false, 'TALLY_ALREADY_DONE');
        assert(self.num_signups.read() != 0, 'SIGNUP_REQUIRED');
        assert(self.keys_added.read() == 0, 'KEYS_ALREADY_ADDED');
        assert(self.message_chain_length.read() == 0, 'MSG_STARTED');
        assert(self.deactivate_batches_processed.read() == 0, 'DEACT_ALREADY_PROCESSED');
    }

    fn assert_can_publish_vote(self: @ContractState) {
        assert(self.tally_submitted.read() == false, 'TALLY_ALREADY_DONE');
        assert(self.keys_added.read() != 0, 'KEY_REQUIRED');
        assert(self.processed_message_count.read() == 0, 'MSG_ALREADY_PROCESSED');
    }

    fn assert_can_process_deactivate(self: @ContractState) {
        assert(self.tally_submitted.read() == false, 'TALLY_ALREADY_DONE');
        assert(self.num_signups.read() != 0, 'SIGNUP_REQUIRED');
        assert(self.deactivate_message_chain_length.read() != 0, 'DMSG_REQUIRED');
        assert(
            self
                .processed_deactivate_message_count
                .read() < self
                .deactivate_message_chain_length
                .read(),
            'ALL_DMSG_DONE',
        );
        assert(self.keys_added.read() == 0, 'KEYS_ALREADY_ADDED');
        assert(self.message_batches_processed.read() == 0, 'MSG_ALREADY_PROCESSED');
    }

    fn assert_can_add_new_key(self: @ContractState) {
        assert(self.tally_submitted.read() == false, 'TALLY_ALREADY_DONE');
        assert(self.num_signups.read() != 0, 'SIGNUP_REQUIRED');
        assert(self.deactivate_message_chain_length.read() != 0, 'DMSG_REQUIRED');
        assert(self.deactivate_batches_processed.read() != 0, 'DEACT_REQUIRED');
        assert(
            self
                .processed_deactivate_message_count
                .read() == self
                .deactivate_message_chain_length
                .read(),
            'DMSG_LEFT',
        );
        assert(self.message_batches_processed.read() == 0, 'MSG_ALREADY_PROCESSED');
        assert(self.message_chain_length.read() == 0, 'MSG_STARTED');
    }

    fn assert_can_process_messages(self: @ContractState) {
        assert(self.tally_submitted.read() == false, 'TALLY_ALREADY_DONE');
        assert(self.deactivate_batches_processed.read() != 0, 'DEACT_REQUIRED');
        assert(self.keys_added.read() != 0, 'KEY_REQUIRED');
        assert(self.message_chain_length.read() != 0, 'MSG_REQUIRED');
        assert(
            self.processed_message_count.read() < self.message_chain_length.read(), 'ALL_MSG_DONE',
        );
    }

    fn assert_can_tally(self: @ContractState) {
        assert(self.tally_submitted.read() == false, 'TALLY_ALREADY_DONE');
        assert(self.keys_added.read() != 0, 'KEY_REQUIRED');
        assert(self.message_batches_processed.read() != 0, 'MSG_REQUIRED');
        assert(self.processed_message_count.read() == self.message_chain_length.read(), 'MSG_LEFT');
    }

    fn append_message(
        ref self: ContractState,
        message: Span<felt252>,
        enc_pub_key_x: felt252,
        enc_pub_key_y: felt252,
        is_deactivate: bool,
    ) {
        assert(message.len() == 10, 'BAD_MESSAGE_LEN');
        let enc_pub_key_hash = poseidon_pair_hash(enc_pub_key_x, enc_pub_key_y);
        assert(enc_pub_key_hash != 0, 'ENC_KEY_ZERO');
        if is_deactivate {
            assert(
                self.used_deactivate_enc_pub_keys.read(enc_pub_key_hash) == false, 'ENC_KEY_USED',
            );
            self.used_deactivate_enc_pub_keys.write(enc_pub_key_hash, true);
            let index = self.deactivate_message_chain_length.read();
            let previous_hash = self.deactivate_message_hashes.read(index);
            let new_hash = message_hash(message, enc_pub_key_x, enc_pub_key_y, previous_hash);
            self.deactivate_message_hashes.write(index + 1, new_hash);
            self.deactivate_message_chain_length.write(index + 1);
            self
                .emit(
                    DeactivateMessagePublished {
                        chain_index: index, message_hash: new_hash, enc_pub_key_hash,
                    },
                );
        } else {
            assert(self.used_enc_pub_keys.read(enc_pub_key_hash) == false, 'ENC_KEY_USED');
            self.used_enc_pub_keys.write(enc_pub_key_hash, true);
            let index = self.message_chain_length.read();
            let previous_hash = self.message_hashes.read(index);
            let new_hash = message_hash(message, enc_pub_key_x, enc_pub_key_y, previous_hash);
            self.message_hashes.write(index + 1, new_hash);
            self.message_chain_length.write(index + 1);
            self
                .emit(
                    MessagePublished {
                        chain_index: index, message_hash: new_hash, enc_pub_key_hash,
                    },
                );
        }
    }

    fn current_message_batch(self: @ContractState) -> (u32, u32) {
        current_batch(self.processed_message_count.read(), self.message_chain_length.read())
    }

    fn current_deactivate_batch(self: @ContractState) -> (u32, u32) {
        current_batch(
            self.processed_deactivate_message_count.read(),
            self.deactivate_message_chain_length.read(),
        )
    }

    fn current_batch(processed: u32, total: u32) -> (u32, u32) {
        let mut end = processed + MESSAGE_BATCH_SIZE;
        if end > total {
            end = total;
        }
        (processed, end)
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'ONLY_ADMIN');
    }

    fn fact_hash(program_hash: felt252, public_output_hash: felt252) -> felt252 {
        poseidon_pair_hash(program_hash, public_output_hash)
    }

    fn plain_fact_hash_for_output(program_hash: felt252, public_output: Span<felt252>) -> felt252 {
        poseidon_pair_hash(program_hash, poseidon_hash_output(public_output))
    }

    fn bootloaded_fact_hash_for_output(
        bootloader_program_hash: felt252, child_program_hash: felt252, child_output: Span<felt252>,
    ) -> felt252 {
        let bootloader_output_hash = bootloader_output_hash(child_program_hash, child_output);
        poseidon_pair_hash(bootloader_program_hash, bootloader_output_hash)
    }

    fn wrapped_bootloaded_fact_hash_for_output(
        wrapper_program_hash: felt252,
        bootloader_program_hash: felt252,
        child_program_hash: felt252,
        child_output: Span<felt252>,
    ) -> felt252 {
        let bootloader_hash = bootloader_output_hash(child_program_hash, child_output);
        let wrapper_output_hash = PoseidonTrait::new()
            .update(1)
            .update(4)
            .update(wrapper_program_hash)
            .update(bootloader_program_hash)
            .update(bootloader_hash)
            .finalize();
        poseidon_pair_hash(bootloader_program_hash, wrapper_output_hash)
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

    fn find_native_tally_output_start(metadata_output: Span<felt252>) -> usize {
        find_native_output_start(
            metadata_output, TALLY_VOTES_NATIVE_CIRCUIT_ID, TALLY_NATIVE_OUTPUT_LEN,
        )
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

    fn assert_native_tally_output_at(
        metadata_output: Span<felt252>,
        start: usize,
        current_state_commitment: felt252,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
    ) {
        assert_native_output_header_at(metadata_output, start, TALLY_VOTES_NATIVE_CIRCUIT_ID);
        assert(*metadata_output.at(start + 8) == current_state_commitment, 'STATE_OUTPUT_BAD');
        assert(*metadata_output.at(start + 9) == current_tally_commitment, 'TALLY_CURRENT_BAD');
        assert(*metadata_output.at(start + 10) == new_tally_commitment, 'TALLY_NEW_BAD');
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

    fn poseidon_hash_output(output: Span<felt252>) -> felt252 {
        let mut output_hash = PoseidonTrait::new();
        for x in output {
            output_hash = output_hash.update(*x);
        }
        output_hash.finalize()
    }

    fn message_hash(
        message: Span<felt252>,
        enc_pub_key_x: felt252,
        enc_pub_key_y: felt252,
        previous_hash: felt252,
    ) -> felt252 {
        let mut state = PoseidonTrait::new();
        let mut i: usize = 0;
        while i < 10 {
            state = state.update(*message.at(i));
            i += 1;
        }
        state.update(enc_pub_key_x).update(enc_pub_key_y).update(previous_hash).finalize()
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

    #[cfg(test)]
    mod tests {
        use super::{
            bootloaded_fact_hash_for_output, fact_hash, plain_fact_hash_for_output,
            poseidon_hash_output, verification_hash, wrapped_bootloaded_fact_hash_for_output,
        };

        #[test]
        fn fact_hash_matches_tally_wrapper_pair_hash_vector() {
            assert(
                fact_hash(
                    0x1234, 0x456,
                ) == 0x49d46086df30505fa5d8e4d48d2a325ef5a3c85b3135b2a3ddfd883bdb56636,
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

        #[test]
        fn output_hash_fact_modes_match_integrity_vectors() {
            let output = [5, 6, 7].span();
            assert(
                poseidon_hash_output(
                    output,
                ) == 0x527e0bd43e6765351997c60384c821d27993806f4d5f991e9a912df7777feb5,
                'OUTPUT_HASH_BAD',
            );

            assert(
                plain_fact_hash_for_output(
                    0x1234, [5, 6, 7].span(),
                ) == 0x14bb0672f8d0b310806201f4342beea32a511e9fbae9f18be454cb7085db171,
                'PLAIN_OUTPUT_FACT_BAD',
            );

            assert(
                bootloaded_fact_hash_for_output(
                    0x5678, 0x1234, [5, 6, 7].span(),
                ) == 0x2a84e80deaf2006759b78a3f6255e7370072d32a63fdc4248df07c3be967f26,
                'BOOT_OUTPUT_FACT_BAD',
            );

            assert(
                wrapped_bootloaded_fact_hash_for_output(
                    0x9abc, 0x5678, 0x1234, [5, 6, 7].span(),
                ) == 0x4c3af6bdb21415b6a3f13006a38ed9d3cdd278b98ee6d3724e410f16fc90bf9,
                'WRAPPED_OUTPUT_FACT_BAD',
            );
        }
    }
}
