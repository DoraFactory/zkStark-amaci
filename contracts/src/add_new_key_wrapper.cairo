#[starknet::interface]
pub trait IAddNewKeyStarkWrapper<TContractState> {
    fn get_state_commitment(self: @TContractState) -> felt252;
    fn get_keys_added(self: @TContractState) -> felt252;
    fn is_key_nullifier_used(self: @TContractState, key_nullifier: felt252) -> bool;
    fn get_expected_plain_fact_hash(self: @TContractState, public_output_hash: felt252) -> felt252;
    fn get_expected_atlantic_metadata_fact_hash(
        self: @TContractState, metadata_program_hash: felt252, metadata_output: Span<felt252>,
    ) -> felt252;
    fn get_expected_verification_hash(self: @TContractState, fact_hash: felt252) -> felt252;
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
}

#[starknet::contract]
pub mod AddNewKeyStarkWrapper {
    use core::hash::HashStateTrait;
    use core::poseidon::PoseidonTrait;
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use crate::integrity_fact_registry::{
        is_fact_hash_valid_with_security, is_verification_hash_valid,
    };

    const PUBLIC_OUTPUT_MAGIC: felt252 = 0x4d414349535441524b; // MACISTARK
    const NATIVE_PUBLIC_OUTPUT_VERSION: felt252 = 2;
    const ADD_NEW_KEY_NATIVE_CIRCUIT_ID: felt252 =
        0x414d4143495f4144445f4b45595f4e4154495645; // AMACI_ADD_KEY_NATIVE
    const STARKNET_POSEIDON_HASH_SCHEME: felt252 =
        0x535441524b4e45545f504f534549444f4e; // STARKNET_POSEIDON
    const SHARP_BOOTLOADER_PROGRAM_HASH: felt252 =
        0x5ab580b04e3532b6b18f81cfa654a05e29dd8e2352d88df1e765a84072db07;
    const ADD_NEW_KEY_NATIVE_OUTPUT_LEN: usize = 19;

    #[storage]
    struct Storage {
        integrity: ContractAddress,
        fact_registry_mode: felt252,
        is_fact_mocked: bool,
        verifier_config_hash: felt252,
        min_security_bits: u32,
        add_new_key_program_hash: felt252,
        used_key_nullifiers: Map<felt252, bool>,
        state_commitment: felt252,
        keys_added: felt252,
        total_facts_accepted: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AddNewKeyFactAccepted: AddNewKeyFactAccepted,
    }

    #[derive(Drop, starknet::Event)]
    struct AddNewKeyFactAccepted {
        key_nullifier: felt252,
        new_state_commitment: felt252,
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
        add_new_key_program_hash: felt252,
        initial_state_commitment: felt252,
    ) {
        self.integrity.write(integrity);
        self.fact_registry_mode.write(fact_registry_mode);
        self.is_fact_mocked.write(is_fact_mocked);
        self.verifier_config_hash.write(verifier_config_hash);
        self.min_security_bits.write(min_security_bits);
        self.add_new_key_program_hash.write(add_new_key_program_hash);
        self.state_commitment.write(initial_state_commitment);
        self.keys_added.write(0);
        self.total_facts_accepted.write(0);
    }

    #[abi(embed_v0)]
    impl AddNewKeyStarkWrapperImpl of super::IAddNewKeyStarkWrapper<ContractState> {
        fn get_state_commitment(self: @ContractState) -> felt252 {
            self.state_commitment.read()
        }

        fn get_keys_added(self: @ContractState) -> felt252 {
            self.keys_added.read()
        }

        fn is_key_nullifier_used(self: @ContractState, key_nullifier: felt252) -> bool {
            self.used_key_nullifiers.read(key_nullifier)
        }

        fn get_expected_plain_fact_hash(
            self: @ContractState, public_output_hash: felt252,
        ) -> felt252 {
            fact_hash(self.add_new_key_program_hash.read(), public_output_hash)
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

        fn submit_add_new_key_fact(
            ref self: ContractState,
            key_nullifier: felt252,
            new_state_commitment: felt252,
            public_output_hash: felt252,
            fact_hash: felt252,
        ) {
            assert(self.used_key_nullifiers.read(key_nullifier) == false, 'KEY_NULLIFIER_USED');
            let verification_hash = validate_plain_fact(@self, public_output_hash, fact_hash);
            accept_add_new_key_fact(
                ref self,
                key_nullifier,
                new_state_commitment,
                public_output_hash,
                fact_hash,
                verification_hash,
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
            assert(self.used_key_nullifiers.read(key_nullifier) == false, 'KEY_NULLIFIER_USED');
            let verification_hash = validate_atlantic_metadata_fact(
                @self, metadata_program_hash, metadata_output, fact_hash,
            );
            let output_start = find_native_output_start(
                metadata_output, ADD_NEW_KEY_NATIVE_CIRCUIT_ID, ADD_NEW_KEY_NATIVE_OUTPUT_LEN,
            );
            assert_native_output_header_at(
                metadata_output, output_start, ADD_NEW_KEY_NATIVE_CIRCUIT_ID,
            );
            assert(*metadata_output.at(output_start + 8) == key_nullifier, 'KEY_NULLIFIER_BAD');
            let public_output_hash = poseidon_hash_output_at(
                metadata_output, output_start, ADD_NEW_KEY_NATIVE_OUTPUT_LEN,
            );
            accept_add_new_key_fact(
                ref self,
                key_nullifier,
                new_state_commitment,
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
            self.add_new_key_program_hash.read(), public_output_hash,
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
        assert(*metadata_output.at(4) == self.add_new_key_program_hash.read(), 'PROGRAM_MISMATCH');
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

    fn accept_add_new_key_fact(
        ref self: ContractState,
        key_nullifier: felt252,
        new_state_commitment: felt252,
        public_output_hash: felt252,
        fact_hash: felt252,
        verification_hash: felt252,
    ) {
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
