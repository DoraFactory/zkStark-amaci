#[starknet::interface]
pub trait IAmaciRound<TContractState> {
    fn set_program_hash_allowed(ref self: TContractState, program_hash: felt252, allowed: bool);
    fn set_operator(ref self: TContractState, operator: starknet::ContractAddress);
    fn set_fee_recipient(ref self: TContractState, fee_recipient: starknet::ContractAddress);
    fn set_voting_time(ref self: TContractState, start_time: u64, end_time: u64);
    fn set_round_info(ref self: TContractState, title: felt252, metadata_uri_hash: felt252);
    fn set_vote_options(ref self: TContractState, vote_options: Span<felt252>);
    fn set_static_whitelist_user(
        ref self: TContractState,
        user: starknet::ContractAddress,
        voice_credit_balance: felt252,
        allowed: bool,
    );
    fn set_oracle_signup_authorization(
        ref self: TContractState,
        pub_key_hash: felt252,
        voice_credit_balance: felt252,
        allowed: bool,
    );
    fn sign_up(
        ref self: TContractState,
        pub_key_x: felt252,
        pub_key_y: felt252,
        dynamic_voice_credit_balance: felt252,
    );
    fn publish_message(
        ref self: TContractState,
        message: Span<felt252>,
        enc_pub_key_x: felt252,
        enc_pub_key_y: felt252,
    );
    fn publish_message_batch(
        ref self: TContractState, messages: Span<felt252>, enc_pub_keys: Span<felt252>,
    );
    fn publish_deactivate_message(
        ref self: TContractState,
        message: Span<felt252>,
        enc_pub_key_x: felt252,
        enc_pub_key_y: felt252,
    );
    fn start_process_period(ref self: TContractState);
    fn stop_processing_period(ref self: TContractState);
    fn stop_tallying_period(ref self: TContractState, results: Span<felt252>, salt: felt252);
    fn submit_add_new_key_atlantic_metadata_fact(
        ref self: TContractState,
        new_pub_key_x: felt252,
        new_pub_key_y: felt252,
        key_nullifier: felt252,
        metadata_program_hash: felt252,
        metadata_output: Span<felt252>,
        fact_hash: felt252,
    );
    fn submit_process_deactivate_atlantic_metadata_fact(
        ref self: TContractState,
        current_deactivate_commitment: felt252,
        new_deactivate_commitment: felt252,
        metadata_program_hash: felt252,
        metadata_output: Span<felt252>,
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
    fn submit_tally_atlantic_metadata_fact(
        ref self: TContractState,
        current_tally_commitment: felt252,
        new_tally_commitment: felt252,
        metadata_program_hash: felt252,
        metadata_output: Span<felt252>,
        fact_hash: felt252,
    );
    fn get_expected_bootloaded_fact_hash_for_output(
        self: @TContractState,
        bootloader_program_hash: felt252,
        child_program_hash: felt252,
        child_output: Span<felt252>,
    ) -> felt252;
    fn get_expected_verification_hash(self: @TContractState, fact_hash: felt252) -> felt252;
    fn is_program_hash_allowed(self: @TContractState, program_hash: felt252) -> bool;
    fn get_admin(self: @TContractState) -> starknet::ContractAddress;
    fn get_operator(self: @TContractState) -> starknet::ContractAddress;
    fn get_fee_recipient(self: @TContractState) -> starknet::ContractAddress;
    fn get_period(self: @TContractState) -> felt252;
    fn get_poll_id(self: @TContractState) -> felt252;
    fn get_round_title(self: @TContractState) -> felt252;
    fn get_round_metadata_uri_hash(self: @TContractState) -> felt252;
    fn get_state_root(self: @TContractState) -> felt252;
    fn get_state_commitment(self: @TContractState) -> felt252;
    fn get_deactivate_root(self: @TContractState) -> felt252;
    fn get_deactivate_commitment(self: @TContractState) -> felt252;
    fn get_tally_commitment(self: @TContractState) -> felt252;
    fn get_num_signups(self: @TContractState) -> u32;
    fn get_message_chain_length(self: @TContractState) -> u32;
    fn get_deactivate_message_chain_length(self: @TContractState) -> u32;
    fn get_processed_message_count(self: @TContractState) -> u32;
    fn get_processed_deactivate_message_count(self: @TContractState) -> u32;
    fn get_processed_user_count(self: @TContractState) -> u32;
    fn get_total_facts_accepted(self: @TContractState) -> felt252;
    fn get_message_hash(self: @TContractState, index: u32) -> felt252;
    fn get_deactivate_message_hash(self: @TContractState, index: u32) -> felt252;
    fn get_vote_option(self: @TContractState, index: u32) -> felt252;
    fn get_vote_options_len(self: @TContractState) -> u32;
    fn get_result(self: @TContractState, index: u32) -> felt252;
    fn get_total_result(self: @TContractState) -> felt252;
    fn is_key_nullifier_used(self: @TContractState, key_nullifier: felt252) -> bool;
    fn is_registered_pub_key(self: @TContractState, pub_key_hash: felt252) -> bool;
}

#[starknet::contract]
pub mod AmaciRound {
    use core::hash::HashStateTrait;
    use core::num::traits::Zero;
    use core::poseidon::PoseidonTrait;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
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

    const PERIOD_PENDING: felt252 = 0;
    const PERIOD_PROCESSING: felt252 = 1;
    const PERIOD_TALLYING: felt252 = 2;
    const PERIOD_ENDED: felt252 = 3;

    const REGISTRATION_STATIC_WHITELIST: felt252 = 0;
    const REGISTRATION_ORACLE_AUTHORIZED: felt252 = 1;
    const REGISTRATION_PREPOPULATED: felt252 = 2;
    const VOICE_CREDIT_UNIFIED: felt252 = 0;
    const VOICE_CREDIT_DYNAMIC: felt252 = 1;

    const SUPPORTED_STATE_TREE_DEPTH: u32 = 2;
    const SUPPORTED_INT_STATE_TREE_DEPTH: u32 = 1;
    const SUPPORTED_VOTE_OPTION_TREE_DEPTH: u32 = 1;
    const SUPPORTED_MESSAGE_BATCH_SIZE: u32 = 3;
    const SUPPORTED_DEACTIVATE_TREE_DEPTH: u32 = 4;
    const MAX_SIGNUPS: u32 = 25;
    const MAX_VOTE_OPTIONS: u32 = 5;

    const TALLY_NATIVE_OUTPUT_LEN: usize = 12;
    const ADD_NEW_KEY_NATIVE_OUTPUT_LEN: usize = 19;
    const PROCESS_MESSAGES_NATIVE_OUTPUT_LEN: usize = 16;
    const PROCESS_DEACTIVATE_NATIVE_OUTPUT_LEN: usize = 16;

    const TWO_POW_32: felt252 = 0x100000000;
    const TWO_POW_64: felt252 = 0x10000000000000000;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        operator: ContractAddress,
        fee_recipient: ContractAddress,
        period: felt252,
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
        poll_id: felt252,
        coordinator_pub_key_hash: felt252,
        state_tree_depth: u32,
        int_state_tree_depth: u32,
        vote_option_tree_depth: u32,
        deactivate_tree_depth: u32,
        message_batch_size: u32,
        is_quadratic_cost: felt252,
        registration_mode: felt252,
        voice_credit_mode: felt252,
        unified_voice_credit_balance: felt252,
        new_key_voice_credit_balance: felt252,
        deactivate_enabled: bool,
        voting_start_time: u64,
        voting_end_time: u64,
        round_title: felt252,
        round_metadata_uri_hash: felt252,
        vote_options_len: u32,
        vote_options: Map<u32, felt252>,
        whitelist_allowed: Map<ContractAddress, bool>,
        whitelist_voice_credit_balance: Map<ContractAddress, felt252>,
        registered_addresses: Map<ContractAddress, bool>,
        oracle_authorized: Map<felt252, bool>,
        oracle_voice_credit_balance: Map<felt252, felt252>,
        registered_pub_keys: Map<felt252, bool>,
        pub_key_signup_index: Map<felt252, u32>,
        voice_credit_by_index: Map<u32, felt252>,
        state_leaf_hashes: Map<u32, felt252>,
        state_root: felt252,
        state_salt: felt252,
        state_commitment: felt252,
        deactivate_root: felt252,
        deactivate_commitment: felt252,
        tally_commitment: felt252,
        used_key_nullifiers: Map<felt252, bool>,
        used_enc_pub_keys: Map<felt252, bool>,
        used_deactivate_enc_pub_keys: Map<felt252, bool>,
        message_hashes: Map<u32, felt252>,
        deactivate_message_hashes: Map<u32, felt252>,
        num_signups: u32,
        message_chain_length: u32,
        deactivate_message_chain_length: u32,
        processed_message_count: u32,
        processed_deactivate_message_count: u32,
        processed_user_count: u32,
        tally_batches_processed: u32,
        total_facts_accepted: felt252,
        results: Map<u32, felt252>,
        results_len: u32,
        total_result: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ProgramHashAllowedSet: ProgramHashAllowedSet,
        RoundInfoSet: RoundInfoSet,
        VotingTimeSet: VotingTimeSet,
        VoteOptionsSet: VoteOptionsSet,
        StaticWhitelistUserSet: StaticWhitelistUserSet,
        OracleSignupAuthorizationSet: OracleSignupAuthorizationSet,
        SignUp: SignUp,
        MessagePublished: MessagePublished,
        DeactivateMessagePublished: DeactivateMessagePublished,
        ProcessPeriodStarted: ProcessPeriodStarted,
        ProcessingPeriodStopped: ProcessingPeriodStopped,
        AddNewKeyFactAccepted: AddNewKeyFactAccepted,
        ProcessDeactivateFactAccepted: ProcessDeactivateFactAccepted,
        ProcessMessagesFactAccepted: ProcessMessagesFactAccepted,
        TallyFactAccepted: TallyFactAccepted,
        TallyingPeriodStopped: TallyingPeriodStopped,
    }

    #[derive(Drop, starknet::Event)]
    struct ProgramHashAllowedSet {
        program_hash: felt252,
        allowed: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct RoundInfoSet {
        title: felt252,
        metadata_uri_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct VotingTimeSet {
        start_time: u64,
        end_time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct VoteOptionsSet {
        vote_options_len: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct StaticWhitelistUserSet {
        user: ContractAddress,
        voice_credit_balance: felt252,
        allowed: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct OracleSignupAuthorizationSet {
        pub_key_hash: felt252,
        voice_credit_balance: felt252,
        allowed: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct SignUp {
        user: ContractAddress,
        pub_key_hash: felt252,
        state_index: u32,
        voice_credit_balance: felt252,
        state_root: felt252,
        state_commitment: felt252,
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
    struct ProcessPeriodStarted {
        state_commitment: felt252,
        deactivate_commitment: felt252,
        message_chain_length: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct ProcessingPeriodStopped {
        processed_message_count: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct AddNewKeyFactAccepted {
        key_nullifier: felt252,
        new_pub_key_hash: felt252,
        state_index: u32,
        fact_hash: felt252,
        verification_hash: felt252,
        state_root: felt252,
        state_commitment: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ProcessDeactivateFactAccepted {
        old_deactivate_commitment: felt252,
        new_deactivate_commitment: felt252,
        new_deactivate_root: felt252,
        batch_start_index: u32,
        batch_end_index: u32,
        fact_hash: felt252,
        verification_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ProcessMessagesFactAccepted {
        old_state_commitment: felt252,
        new_state_commitment: felt252,
        deactivate_commitment: felt252,
        batch_start_index: u32,
        batch_end_index: u32,
        fact_hash: felt252,
        verification_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct TallyFactAccepted {
        old_tally_commitment: felt252,
        new_tally_commitment: felt252,
        batch_num: u32,
        processed_user_count: u32,
        fact_hash: felt252,
        verification_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct TallyingPeriodStopped {
        results_len: u32,
        total_result: felt252,
        tally_commitment: felt252,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        admin: ContractAddress,
        operator: ContractAddress,
        fee_recipient: ContractAddress,
        integrity: ContractAddress,
        fact_registry_mode: felt252,
        is_fact_mocked: bool,
        verifier_config_hash: felt252,
        min_security_bits: u32,
        add_new_key_program_hash: felt252,
        process_messages_program_hash: felt252,
        process_deactivate_program_hash: felt252,
        tally_program_hash: felt252,
        poll_id: felt252,
        coordinator_pub_key_hash: felt252,
        state_salt: felt252,
        deactivate_root: felt252,
        deactivate_commitment: felt252,
        registration_mode: felt252,
        voice_credit_mode: felt252,
        unified_voice_credit_balance: felt252,
        new_key_voice_credit_balance: felt252,
        deactivate_enabled: bool,
        voting_start_time: u64,
        voting_end_time: u64,
        is_quadratic_cost: felt252,
        vote_options: Span<felt252>,
    ) {
        assert(admin.is_non_zero(), 'ADMIN_ZERO');
        assert(operator.is_non_zero(), 'OPERATOR_ZERO');
        assert(voting_start_time < voting_end_time, 'BAD_VOTING_TIME');
        assert(
            registration_mode == REGISTRATION_STATIC_WHITELIST
                || registration_mode == REGISTRATION_ORACLE_AUTHORIZED
                || registration_mode == REGISTRATION_PREPOPULATED,
            'BAD_REG_MODE',
        );
        assert(
            voice_credit_mode == VOICE_CREDIT_UNIFIED || voice_credit_mode == VOICE_CREDIT_DYNAMIC,
            'BAD_VC_MODE',
        );
        assert(is_quadratic_cost == 0 || is_quadratic_cost == 1, 'BAD_CIRCUIT_TYPE');
        assert(vote_options.len() > 0, 'NO_VOTE_OPTIONS');
        assert(vote_options.len() <= MAX_VOTE_OPTIONS.into(), 'TOO_MANY_OPTIONS');
        assert(poll_id != 0, 'POLL_ID_ZERO');
        assert(coordinator_pub_key_hash != 0, 'COORD_KEY_ZERO');

        self.admin.write(admin);
        self.operator.write(operator);
        self.fee_recipient.write(fee_recipient);
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
        self.poll_id.write(poll_id);
        self.coordinator_pub_key_hash.write(coordinator_pub_key_hash);
        self.state_tree_depth.write(SUPPORTED_STATE_TREE_DEPTH);
        self.int_state_tree_depth.write(SUPPORTED_INT_STATE_TREE_DEPTH);
        self.vote_option_tree_depth.write(SUPPORTED_VOTE_OPTION_TREE_DEPTH);
        self.deactivate_tree_depth.write(SUPPORTED_DEACTIVATE_TREE_DEPTH);
        self.message_batch_size.write(SUPPORTED_MESSAGE_BATCH_SIZE);
        self.registration_mode.write(registration_mode);
        self.voice_credit_mode.write(voice_credit_mode);
        self.unified_voice_credit_balance.write(unified_voice_credit_balance);
        self.new_key_voice_credit_balance.write(new_key_voice_credit_balance);
        self.deactivate_enabled.write(deactivate_enabled);
        self.voting_start_time.write(voting_start_time);
        self.voting_end_time.write(voting_end_time);
        self.is_quadratic_cost.write(is_quadratic_cost);

        let state_root = zero_state_root();
        self.state_root.write(state_root);
        self.state_salt.write(state_salt);
        self.state_commitment.write(poseidon_pair_hash(state_root, state_salt));
        self.deactivate_root.write(deactivate_root);
        self.deactivate_commitment.write(deactivate_commitment);
        self.tally_commitment.write(0);
        self.period.write(PERIOD_PENDING);
        self.message_hashes.write(0, 0);
        self.deactivate_message_hashes.write(0, 0);

        let mut option_count: u32 = 0;
        for option in vote_options {
            self.vote_options.write(option_count, *option);
            option_count += 1;
        }
        self.vote_options_len.write(option_count);
    }

    #[abi(embed_v0)]
    impl AmaciRoundImpl of super::IAmaciRound<ContractState> {
        fn set_program_hash_allowed(ref self: ContractState, program_hash: felt252, allowed: bool) {
            assert_admin(@self);
            self.allowed_program_hashes.write(program_hash, allowed);
            self.emit(ProgramHashAllowedSet { program_hash, allowed });
        }

        fn set_operator(ref self: ContractState, operator: ContractAddress) {
            assert_admin(@self);
            assert(operator.is_non_zero(), 'OPERATOR_ZERO');
            self.operator.write(operator);
        }

        fn set_fee_recipient(ref self: ContractState, fee_recipient: ContractAddress) {
            assert_admin(@self);
            self.fee_recipient.write(fee_recipient);
        }

        fn set_voting_time(ref self: ContractState, start_time: u64, end_time: u64) {
            assert_admin(@self);
            assert_period(@self, PERIOD_PENDING);
            assert(start_time < end_time, 'BAD_VOTING_TIME');
            assert(get_block_timestamp() < start_time, 'VOTING_STARTED');
            self.voting_start_time.write(start_time);
            self.voting_end_time.write(end_time);
            self.emit(VotingTimeSet { start_time, end_time });
        }

        fn set_round_info(ref self: ContractState, title: felt252, metadata_uri_hash: felt252) {
            assert_admin(@self);
            self.round_title.write(title);
            self.round_metadata_uri_hash.write(metadata_uri_hash);
            self.emit(RoundInfoSet { title, metadata_uri_hash });
        }

        fn set_vote_options(ref self: ContractState, vote_options: Span<felt252>) {
            assert_admin(@self);
            assert_period(@self, PERIOD_PENDING);
            assert(get_block_timestamp() < self.voting_start_time.read(), 'VOTING_STARTED');
            assert(vote_options.len() > 0, 'NO_VOTE_OPTIONS');
            assert(vote_options.len() <= MAX_VOTE_OPTIONS.into(), 'TOO_MANY_OPTIONS');
            let mut option_count: u32 = 0;
            for option in vote_options {
                self.vote_options.write(option_count, *option);
                option_count += 1;
            }
            self.vote_options_len.write(option_count);
            self.emit(VoteOptionsSet { vote_options_len: option_count });
        }

        fn set_static_whitelist_user(
            ref self: ContractState,
            user: ContractAddress,
            voice_credit_balance: felt252,
            allowed: bool,
        ) {
            assert_admin(@self);
            assert_period(@self, PERIOD_PENDING);
            assert(user.is_non_zero(), 'USER_ZERO');
            if allowed {
                assert(voice_credit_balance != 0, 'VC_ZERO');
            }
            self.whitelist_allowed.write(user, allowed);
            self.whitelist_voice_credit_balance.write(user, voice_credit_balance);
            self.emit(StaticWhitelistUserSet { user, voice_credit_balance, allowed });
        }

        fn set_oracle_signup_authorization(
            ref self: ContractState,
            pub_key_hash: felt252,
            voice_credit_balance: felt252,
            allowed: bool,
        ) {
            assert_operator_or_admin(@self);
            assert_period(@self, PERIOD_PENDING);
            assert(pub_key_hash != 0, 'PUB_KEY_ZERO');
            if allowed {
                assert(voice_credit_balance != 0, 'VC_ZERO');
            }
            self.oracle_authorized.write(pub_key_hash, allowed);
            self.oracle_voice_credit_balance.write(pub_key_hash, voice_credit_balance);
            self.emit(OracleSignupAuthorizationSet { pub_key_hash, voice_credit_balance, allowed });
        }

        fn sign_up(
            ref self: ContractState,
            pub_key_x: felt252,
            pub_key_y: felt252,
            dynamic_voice_credit_balance: felt252,
        ) {
            assert_voting_open(@self);
            let registration_mode = self.registration_mode.read();
            assert(registration_mode != REGISTRATION_PREPOPULATED, 'SIGNUP_DISABLED');
            let pub_key_hash = poseidon_pair_hash(pub_key_x, pub_key_y);
            assert(pub_key_hash != 0, 'PUB_KEY_ZERO');
            assert(self.registered_pub_keys.read(pub_key_hash) == false, 'PUB_KEY_REGISTERED');
            assert(self.num_signups.read() < MAX_SIGNUPS, 'STATE_TREE_FULL');

            let caller = get_caller_address();
            let voice_credit_balance = resolve_signup_voice_credit(
                ref self, registration_mode, caller, pub_key_hash, dynamic_voice_credit_balance,
            );
            append_state_leaf(ref self, pub_key_x, pub_key_y, voice_credit_balance);
            self.registered_pub_keys.write(pub_key_hash, true);
            self.pub_key_signup_index.write(pub_key_hash, self.num_signups.read() - 1);
            self.registered_addresses.write(caller, true);
            self
                .emit(
                    SignUp {
                        user: caller,
                        pub_key_hash,
                        state_index: self.num_signups.read() - 1,
                        voice_credit_balance,
                        state_root: self.state_root.read(),
                        state_commitment: self.state_commitment.read(),
                    },
                );
        }

        fn publish_message(
            ref self: ContractState,
            message: Span<felt252>,
            enc_pub_key_x: felt252,
            enc_pub_key_y: felt252,
        ) {
            assert_voting_open(@self);
            append_message(ref self, message, enc_pub_key_x, enc_pub_key_y, false);
        }

        fn publish_message_batch(
            ref self: ContractState, messages: Span<felt252>, enc_pub_keys: Span<felt252>,
        ) {
            assert_voting_open(@self);
            assert(messages.len() % 10 == 0, 'BAD_MESSAGES_LEN');
            let batch_len = messages.len() / 10;
            assert(enc_pub_keys.len() == batch_len * 2, 'BAD_KEYS_LEN');
            let mut i: usize = 0;
            while i < batch_len {
                append_message_at(ref self, messages, i * 10, enc_pub_keys, i * 2, false);
                i += 1;
            }
        }

        fn publish_deactivate_message(
            ref self: ContractState,
            message: Span<felt252>,
            enc_pub_key_x: felt252,
            enc_pub_key_y: felt252,
        ) {
            assert(self.deactivate_enabled.read(), 'DEACT_DISABLED');
            assert_voting_open(@self);
            append_message(ref self, message, enc_pub_key_x, enc_pub_key_y, true);
        }

        fn start_process_period(ref self: ContractState) {
            assert_operator_or_admin(@self);
            assert_period(@self, PERIOD_PENDING);
            assert(get_block_timestamp() >= self.voting_end_time.read(), 'VOTING_ACTIVE');
            assert(
                self
                    .processed_deactivate_message_count
                    .read() == self
                    .deactivate_message_chain_length
                    .read(),
                'DMSG_LEFT',
            );
            self.write_period(PERIOD_PROCESSING);
            self
                .emit(
                    ProcessPeriodStarted {
                        state_commitment: self.state_commitment.read(),
                        deactivate_commitment: self.deactivate_commitment.read(),
                        message_chain_length: self.message_chain_length.read(),
                    },
                );
        }

        fn stop_processing_period(ref self: ContractState) {
            assert_operator_or_admin(@self);
            assert_period(@self, PERIOD_PROCESSING);
            assert(
                self.processed_message_count.read() == self.message_chain_length.read(), 'MSG_LEFT',
            );
            self.write_period(PERIOD_TALLYING);
            self
                .emit(
                    ProcessingPeriodStopped {
                        processed_message_count: self.processed_message_count.read(),
                    },
                );
        }

        fn stop_tallying_period(ref self: ContractState, results: Span<felt252>, salt: felt252) {
            assert_operator_or_admin(@self);
            assert_period(@self, PERIOD_TALLYING);
            assert(self.processed_user_count.read() >= self.num_signups.read(), 'USERS_LEFT');
            assert(results.len() <= self.vote_options_len.read().into(), 'RESULTS_TOO_LONG');
            assert(results.len() <= MAX_VOTE_OPTIONS.into(), 'RESULTS_TOO_LONG');

            let results_root = results_root_depth_1(results);
            let commitment = poseidon_pair_hash(results_root, salt);
            assert(self.tally_commitment.read() == commitment, 'TALLY_COMMIT_BAD');

            let mut total = 0;
            let mut result_count: u32 = 0;
            for result in results {
                self.results.write(result_count, *result);
                total += *result;
                result_count += 1;
            }
            self.results_len.write(result_count);
            self.total_result.write(total);
            self.write_period(PERIOD_ENDED);
            self
                .emit(
                    TallyingPeriodStopped {
                        results_len: result_count,
                        total_result: total,
                        tally_commitment: commitment,
                    },
                );
        }

        fn submit_add_new_key_atlantic_metadata_fact(
            ref self: ContractState,
            new_pub_key_x: felt252,
            new_pub_key_y: felt252,
            key_nullifier: felt252,
            metadata_program_hash: felt252,
            metadata_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            assert_operator_or_admin(@self);
            assert_voting_open(@self);
            assert(self.used_key_nullifiers.read(key_nullifier) == false, 'KEY_NULLIFIER_USED');
            assert(self.num_signups.read() < MAX_SIGNUPS, 'STATE_TREE_FULL');
            let new_pub_key_hash = poseidon_pair_hash(new_pub_key_x, new_pub_key_y);
            assert(self.registered_pub_keys.read(new_pub_key_hash) == false, 'PUB_KEY_REGISTERED');
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
                *metadata_output.at(output_start + 4) == self.state_tree_depth.read().into(),
                'STATE_DEPTH_BAD',
            );
            assert(
                *metadata_output.at(output_start + 5) == self.deactivate_tree_depth.read().into(),
                'DEACT_DEPTH_BAD',
            );
            assert(
                *metadata_output.at(output_start + 6) == self.deactivate_root.read(),
                'DEACT_ROOT_BAD',
            );
            assert(
                *metadata_output.at(output_start + 7) == self.coordinator_pub_key_hash.read(),
                'COORD_OUTPUT_BAD',
            );
            assert(*metadata_output.at(output_start + 8) == key_nullifier, 'KEY_NULLIFIER_BAD');
            assert(*metadata_output.at(output_start + 16) == new_pub_key_hash, 'NEW_KEY_BAD');
            assert(*metadata_output.at(output_start + 17) == self.poll_id.read(), 'POLL_ID_BAD');

            self.used_key_nullifiers.write(key_nullifier, true);
            append_state_leaf(
                ref self, new_pub_key_x, new_pub_key_y, self.new_key_voice_credit_balance.read(),
            );
            self.registered_pub_keys.write(new_pub_key_hash, true);
            self.pub_key_signup_index.write(new_pub_key_hash, self.num_signups.read() - 1);
            self.total_facts_accepted.write(self.total_facts_accepted.read() + 1);
            self
                .emit(
                    AddNewKeyFactAccepted {
                        key_nullifier,
                        new_pub_key_hash,
                        state_index: self.num_signups.read() - 1,
                        fact_hash,
                        verification_hash,
                        state_root: self.state_root.read(),
                        state_commitment: self.state_commitment.read(),
                    },
                );
        }

        fn submit_process_deactivate_atlantic_metadata_fact(
            ref self: ContractState,
            current_deactivate_commitment: felt252,
            new_deactivate_commitment: felt252,
            metadata_program_hash: felt252,
            metadata_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            assert_operator_or_admin(@self);
            assert(self.deactivate_enabled.read(), 'DEACT_DISABLED');
            assert_period(@self, PERIOD_PENDING);
            assert(
                self.deactivate_commitment.read() == current_deactivate_commitment,
                'DEACT_MISMATCH',
            );
            assert(
                self
                    .processed_deactivate_message_count
                    .read() < self
                    .deactivate_message_chain_length
                    .read(),
                'ALL_DMSG_DONE',
            );
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
                *metadata_output.at(output_start + 4) == self.state_tree_depth.read().into(),
                'STATE_DEPTH_BAD',
            );
            assert(
                *metadata_output.at(output_start + 5) == self.deactivate_tree_depth.read().into(),
                'DEACT_DEPTH_BAD',
            );
            assert(
                *metadata_output.at(output_start + 6) == self.message_batch_size.read().into(),
                'BATCH_SIZE_BAD',
            );
            assert(
                *metadata_output.at(output_start + 8) == self.coordinator_pub_key_hash.read(),
                'COORD_OUTPUT_BAD',
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
            assert(
                *metadata_output.at(output_start + 13) == self.state_root.read(), 'STATE_ROOT_BAD',
            );
            assert(*metadata_output.at(output_start + 14) == self.poll_id.read(), 'POLL_ID_BAD');

            let new_deactivate_root = *metadata_output.at(output_start + 7);
            self.deactivate_root.write(new_deactivate_root);
            self.deactivate_commitment.write(new_deactivate_commitment);
            self.processed_deactivate_message_count.write(batch_end);
            self.total_facts_accepted.write(self.total_facts_accepted.read() + 1);
            self
                .emit(
                    ProcessDeactivateFactAccepted {
                        old_deactivate_commitment: current_deactivate_commitment,
                        new_deactivate_commitment,
                        new_deactivate_root,
                        batch_start_index: batch_start,
                        batch_end_index: batch_end,
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
            assert_operator_or_admin(@self);
            assert_period(@self, PERIOD_PROCESSING);
            assert(self.state_commitment.read() == current_state_commitment, 'STATE_MISMATCH');
            assert(
                self.deactivate_commitment.read() == current_deactivate_commitment,
                'DEACT_MISMATCH',
            );
            assert(
                self.processed_message_count.read() < self.message_chain_length.read(),
                'ALL_MSG_DONE',
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
                *metadata_output.at(output_start + 4) == self.state_tree_depth.read().into(),
                'STATE_DEPTH_BAD',
            );
            assert(
                *metadata_output.at(output_start + 5) == self.vote_option_tree_depth.read().into(),
                'VOTE_DEPTH_BAD',
            );
            assert(
                *metadata_output.at(output_start + 6) == self.message_batch_size.read().into(),
                'BATCH_SIZE_BAD',
            );
            assert(
                *metadata_output.at(output_start + 7) == packed_process_values(@self), 'PACKED_BAD',
            );
            assert(
                *metadata_output.at(output_start + 8) == self.coordinator_pub_key_hash.read(),
                'COORD_OUTPUT_BAD',
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
            assert(*metadata_output.at(output_start + 14) == self.poll_id.read(), 'POLL_ID_BAD');

            self.state_commitment.write(new_state_commitment);
            self
                .processed_message_count
                .write(self.processed_message_count.read() + batch_end - batch_start);
            self.total_facts_accepted.write(self.total_facts_accepted.read() + 1);
            self
                .emit(
                    ProcessMessagesFactAccepted {
                        old_state_commitment: current_state_commitment,
                        new_state_commitment,
                        deactivate_commitment: current_deactivate_commitment,
                        batch_start_index: batch_start,
                        batch_end_index: batch_end,
                        fact_hash,
                        verification_hash,
                    },
                );
        }

        fn submit_tally_atlantic_metadata_fact(
            ref self: ContractState,
            current_tally_commitment: felt252,
            new_tally_commitment: felt252,
            metadata_program_hash: felt252,
            metadata_output: Span<felt252>,
            fact_hash: felt252,
        ) {
            assert_operator_or_admin(@self);
            assert_period(@self, PERIOD_TALLYING);
            assert(self.tally_commitment.read() == current_tally_commitment, 'TALLY_MISMATCH');
            assert(self.processed_user_count.read() < self.num_signups.read(), 'ALL_USERS_DONE');
            let verification_hash = validate_atlantic_metadata_fact(
                @self,
                self.tally_program_hash.read(),
                metadata_program_hash,
                metadata_output,
                fact_hash,
            );
            let output_start = find_native_output_start(
                metadata_output, TALLY_VOTES_NATIVE_CIRCUIT_ID, TALLY_NATIVE_OUTPUT_LEN,
            );
            let batch_num = self.tally_batches_processed.read();
            assert_native_output_header_at(
                metadata_output, output_start, TALLY_VOTES_NATIVE_CIRCUIT_ID,
            );
            assert(
                *metadata_output.at(output_start + 4) == self.state_tree_depth.read().into(),
                'STATE_DEPTH_BAD',
            );
            assert(
                *metadata_output.at(output_start + 5) == self.int_state_tree_depth.read().into(),
                'INT_DEPTH_BAD',
            );
            assert(
                *metadata_output.at(output_start + 6) == self.vote_option_tree_depth.read().into(),
                'VOTE_DEPTH_BAD',
            );
            assert(
                *metadata_output.at(output_start + 7) == packed_tally_values(@self), 'PACKED_BAD',
            );
            assert(
                *metadata_output.at(output_start + 8) == self.state_commitment.read(),
                'STATE_OUTPUT_BAD',
            );
            assert(
                *metadata_output.at(output_start + 9) == current_tally_commitment,
                'TALLY_CURRENT_BAD',
            );
            assert(*metadata_output.at(output_start + 10) == new_tally_commitment, 'TALLY_NEW_BAD');

            self.tally_commitment.write(new_tally_commitment);
            self.tally_batches_processed.write(batch_num + 1);
            let mut next_processed = self.processed_user_count.read() + tally_batch_size(@self);
            if next_processed > self.num_signups.read() {
                next_processed = self.num_signups.read();
            }
            self.processed_user_count.write(next_processed);
            self.total_facts_accepted.write(self.total_facts_accepted.read() + 1);
            self
                .emit(
                    TallyFactAccepted {
                        old_tally_commitment: current_tally_commitment,
                        new_tally_commitment,
                        batch_num,
                        processed_user_count: next_processed,
                        fact_hash,
                        verification_hash,
                    },
                );
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

        fn get_expected_verification_hash(self: @ContractState, fact_hash: felt252) -> felt252 {
            verification_hash(
                fact_hash, self.verifier_config_hash.read(), self.min_security_bits.read(),
            )
        }

        fn is_program_hash_allowed(self: @ContractState, program_hash: felt252) -> bool {
            self.allowed_program_hashes.read(program_hash)
        }

        fn get_admin(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }

        fn get_operator(self: @ContractState) -> ContractAddress {
            self.operator.read()
        }

        fn get_fee_recipient(self: @ContractState) -> ContractAddress {
            self.fee_recipient.read()
        }

        fn get_period(self: @ContractState) -> felt252 {
            self.read_period()
        }

        fn get_poll_id(self: @ContractState) -> felt252 {
            self.poll_id.read()
        }

        fn get_round_title(self: @ContractState) -> felt252 {
            self.round_title.read()
        }

        fn get_round_metadata_uri_hash(self: @ContractState) -> felt252 {
            self.round_metadata_uri_hash.read()
        }

        fn get_state_root(self: @ContractState) -> felt252 {
            self.state_root.read()
        }

        fn get_state_commitment(self: @ContractState) -> felt252 {
            self.state_commitment.read()
        }

        fn get_deactivate_root(self: @ContractState) -> felt252 {
            self.deactivate_root.read()
        }

        fn get_deactivate_commitment(self: @ContractState) -> felt252 {
            self.deactivate_commitment.read()
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

        fn get_processed_user_count(self: @ContractState) -> u32 {
            self.processed_user_count.read()
        }

        fn get_total_facts_accepted(self: @ContractState) -> felt252 {
            self.total_facts_accepted.read()
        }

        fn get_message_hash(self: @ContractState, index: u32) -> felt252 {
            self.message_hashes.read(index)
        }

        fn get_deactivate_message_hash(self: @ContractState, index: u32) -> felt252 {
            self.deactivate_message_hashes.read(index)
        }

        fn get_vote_option(self: @ContractState, index: u32) -> felt252 {
            assert(index < self.vote_options_len.read(), 'OPTION_OOB');
            self.vote_options.read(index)
        }

        fn get_vote_options_len(self: @ContractState) -> u32 {
            self.vote_options_len.read()
        }

        fn get_result(self: @ContractState, index: u32) -> felt252 {
            assert(index < self.results_len.read(), 'RESULT_OOB');
            self.results.read(index)
        }

        fn get_total_result(self: @ContractState) -> felt252 {
            self.total_result.read()
        }

        fn is_key_nullifier_used(self: @ContractState, key_nullifier: felt252) -> bool {
            self.used_key_nullifiers.read(key_nullifier)
        }

        fn is_registered_pub_key(self: @ContractState, pub_key_hash: felt252) -> bool {
            self.registered_pub_keys.read(pub_key_hash)
        }
    }

    #[generate_trait]
    impl InternalStateImpl of InternalStateTrait {
        fn read_period(self: @ContractState) -> felt252 {
            self.period.read()
        }

        fn write_period(ref self: ContractState, period: felt252) {
            self.period.write(period);
        }
    }

    fn resolve_signup_voice_credit(
        ref self: ContractState,
        registration_mode: felt252,
        caller: ContractAddress,
        pub_key_hash: felt252,
        dynamic_voice_credit_balance: felt252,
    ) -> felt252 {
        if registration_mode == REGISTRATION_STATIC_WHITELIST {
            assert(self.whitelist_allowed.read(caller), 'NOT_WHITELISTED');
            assert(self.registered_addresses.read(caller) == false, 'ADDR_REGISTERED');
            if self.voice_credit_mode.read() == VOICE_CREDIT_UNIFIED {
                let balance = self.unified_voice_credit_balance.read();
                assert(balance != 0, 'VC_ZERO');
                balance
            } else {
                let balance = self.whitelist_voice_credit_balance.read(caller);
                assert(balance != 0, 'VC_ZERO');
                balance
            }
        } else {
            assert(registration_mode == REGISTRATION_ORACLE_AUTHORIZED, 'BAD_REG_MODE');
            assert(self.oracle_authorized.read(pub_key_hash), 'ORACLE_NOT_AUTH');
            self.oracle_authorized.write(pub_key_hash, false);
            if self.voice_credit_mode.read() == VOICE_CREDIT_UNIFIED {
                let balance = self.unified_voice_credit_balance.read();
                assert(balance != 0, 'VC_ZERO');
                balance
            } else {
                let balance = self.oracle_voice_credit_balance.read(pub_key_hash);
                assert(balance == dynamic_voice_credit_balance, 'VC_MISMATCH');
                assert(balance != 0, 'VC_ZERO');
                balance
            }
        }
    }

    fn append_state_leaf(
        ref self: ContractState,
        pub_key_x: felt252,
        pub_key_y: felt252,
        voice_credit_balance: felt252,
    ) {
        assert(voice_credit_balance != 0, 'VC_ZERO');
        let index = self.num_signups.read();
        let leaf_hash = state_leaf_hash(pub_key_x, pub_key_y, voice_credit_balance);
        self.state_leaf_hashes.write(index, leaf_hash);
        self.voice_credit_by_index.write(index, voice_credit_balance);
        self.num_signups.write(index + 1);
        recompute_state_root(ref self);
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
            let new_hash = message_hash(message, 0, enc_pub_key_x, enc_pub_key_y, previous_hash);
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
            let new_hash = message_hash(message, 0, enc_pub_key_x, enc_pub_key_y, previous_hash);
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

    fn append_message_at(
        ref self: ContractState,
        messages: Span<felt252>,
        message_start: usize,
        enc_pub_keys: Span<felt252>,
        key_start: usize,
        is_deactivate: bool,
    ) {
        let enc_pub_key_x = *enc_pub_keys.at(key_start);
        let enc_pub_key_y = *enc_pub_keys.at(key_start + 1);
        let enc_pub_key_hash = poseidon_pair_hash(enc_pub_key_x, enc_pub_key_y);
        assert(enc_pub_key_hash != 0, 'ENC_KEY_ZERO');
        let message_view = messages;
        if is_deactivate {
            assert(
                self.used_deactivate_enc_pub_keys.read(enc_pub_key_hash) == false, 'ENC_KEY_USED',
            );
            self.used_deactivate_enc_pub_keys.write(enc_pub_key_hash, true);
            let index = self.deactivate_message_chain_length.read();
            let previous_hash = self.deactivate_message_hashes.read(index);
            let new_hash = message_hash(
                message_view, message_start, enc_pub_key_x, enc_pub_key_y, previous_hash,
            );
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
            let new_hash = message_hash(
                message_view, message_start, enc_pub_key_x, enc_pub_key_y, previous_hash,
            );
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

    fn recompute_state_root(ref self: ContractState) {
        let root = compute_state_root_from_storage(@self);
        self.state_root.write(root);
        self.state_commitment.write(poseidon_pair_hash(root, self.state_salt.read()));
    }

    fn compute_state_root_from_storage(self: @ContractState) -> felt252 {
        let g0 = hash5(
            self.state_leaf_hashes.read(0),
            self.state_leaf_hashes.read(1),
            self.state_leaf_hashes.read(2),
            self.state_leaf_hashes.read(3),
            self.state_leaf_hashes.read(4),
        );
        let g1 = hash5(
            self.state_leaf_hashes.read(5),
            self.state_leaf_hashes.read(6),
            self.state_leaf_hashes.read(7),
            self.state_leaf_hashes.read(8),
            self.state_leaf_hashes.read(9),
        );
        let g2 = hash5(
            self.state_leaf_hashes.read(10),
            self.state_leaf_hashes.read(11),
            self.state_leaf_hashes.read(12),
            self.state_leaf_hashes.read(13),
            self.state_leaf_hashes.read(14),
        );
        let g3 = hash5(
            self.state_leaf_hashes.read(15),
            self.state_leaf_hashes.read(16),
            self.state_leaf_hashes.read(17),
            self.state_leaf_hashes.read(18),
            self.state_leaf_hashes.read(19),
        );
        let g4 = hash5(
            self.state_leaf_hashes.read(20),
            self.state_leaf_hashes.read(21),
            self.state_leaf_hashes.read(22),
            self.state_leaf_hashes.read(23),
            self.state_leaf_hashes.read(24),
        );
        hash5(g0, g1, g2, g3, g4)
    }

    fn current_message_batch(self: @ContractState) -> (u32, u32) {
        let chain_len = self.message_chain_length.read();
        let processed = self.processed_message_count.read();
        let batch_size = self.message_batch_size.read();
        let remaining = chain_len - processed;
        assert(remaining > 0, 'NO_MSG_BATCH');
        let batch_start = ((remaining - 1) / batch_size) * batch_size;
        let mut batch_end = batch_start + batch_size;
        if batch_end > chain_len {
            batch_end = chain_len;
        }
        (batch_start, batch_end)
    }

    fn current_deactivate_batch(self: @ContractState) -> (u32, u32) {
        let batch_start = self.processed_deactivate_message_count.read();
        let mut batch_end = batch_start + self.message_batch_size.read();
        if batch_end > self.deactivate_message_chain_length.read() {
            batch_end = self.deactivate_message_chain_length.read();
        }
        (batch_start, batch_end)
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

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'ONLY_ADMIN');
    }

    fn assert_operator_or_admin(self: @ContractState) {
        let caller = get_caller_address();
        assert(caller == self.operator.read() || caller == self.admin.read(), 'ONLY_OPERATOR');
    }

    fn assert_period(self: @ContractState, period: felt252) {
        assert(self.read_period() == period, 'BAD_PERIOD');
    }

    fn assert_voting_open(self: @ContractState) {
        assert_period(self, PERIOD_PENDING);
        let now = get_block_timestamp();
        assert(now >= self.voting_start_time.read(), 'VOTING_NOT_STARTED');
        assert(now < self.voting_end_time.read(), 'VOTING_ENDED');
    }

    fn packed_process_values(self: @ContractState) -> felt252 {
        self.is_quadratic_cost.read() * TWO_POW_64
            + self.num_signups.read().into() * TWO_POW_32
            + self.vote_options_len.read().into()
    }

    fn packed_tally_values(self: @ContractState) -> felt252 {
        self.num_signups.read().into() * TWO_POW_32 + self.tally_batches_processed.read().into()
    }

    fn tally_batch_size(self: @ContractState) -> u32 {
        let depth = self.int_state_tree_depth.read();
        if depth == 0 {
            1
        } else {
            5
        }
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

    fn verification_hash(
        fact_hash: felt252, verifier_config_hash: felt252, security_bits: u32,
    ) -> felt252 {
        PoseidonTrait::new()
            .update(fact_hash)
            .update(verifier_config_hash)
            .update(security_bits.into())
            .finalize()
    }

    fn message_hash(
        message: Span<felt252>,
        start: usize,
        enc_pub_key_x: felt252,
        enc_pub_key_y: felt252,
        previous_hash: felt252,
    ) -> felt252 {
        let mut state = PoseidonTrait::new();
        let mut i: usize = 0;
        while i < 10 {
            state = state.update(*message.at(start + i));
            i += 1;
        }
        state.update(enc_pub_key_x).update(enc_pub_key_y).update(previous_hash).finalize()
    }

    fn state_leaf_hash(
        pub_key_x: felt252, pub_key_y: felt252, voice_credit_balance: felt252,
    ) -> felt252 {
        hash10(pub_key_x, pub_key_y, voice_credit_balance, zero_vote_root(), 0, 0, 0, 0, 0, 0)
    }

    fn results_root_depth_1(results: Span<felt252>) -> felt252 {
        let v0 = if results.len() > 0 {
            *results.at(0)
        } else {
            0
        };
        let v1 = if results.len() > 1 {
            *results.at(1)
        } else {
            0
        };
        let v2 = if results.len() > 2 {
            *results.at(2)
        } else {
            0
        };
        let v3 = if results.len() > 3 {
            *results.at(3)
        } else {
            0
        };
        let v4 = if results.len() > 4 {
            *results.at(4)
        } else {
            0
        };
        hash5(v0, v1, v2, v3, v4)
    }

    fn zero_vote_root() -> felt252 {
        hash5(0, 0, 0, 0, 0)
    }

    fn zero_state_root() -> felt252 {
        let zero_subroot = hash5(0, 0, 0, 0, 0);
        hash5(zero_subroot, zero_subroot, zero_subroot, zero_subroot, zero_subroot)
    }

    fn hash10(
        v0: felt252,
        v1: felt252,
        v2: felt252,
        v3: felt252,
        v4: felt252,
        v5: felt252,
        v6: felt252,
        v7: felt252,
        v8: felt252,
        v9: felt252,
    ) -> felt252 {
        poseidon_pair_hash(hash5(v0, v1, v2, v3, v4), hash5(v5, v6, v7, v8, v9))
    }

    fn hash5(v0: felt252, v1: felt252, v2: felt252, v3: felt252, v4: felt252) -> felt252 {
        PoseidonTrait::new().update(v0).update(v1).update(v2).update(v3).update(v4).finalize()
    }

    fn poseidon_pair_hash(left: felt252, right: felt252) -> felt252 {
        PoseidonTrait::new().update(left).update(right).finalize()
    }
}
