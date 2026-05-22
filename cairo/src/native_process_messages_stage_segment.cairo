use crate::native_process_message_components::{
    NativeProcessMessageCoordKeyPublicFields as CoordKeyFields,
    NativeProcessMessageCoordKeyWitness as CoordKeyWitness,
    NativeProcessMessageDecryptPublicFields as DecryptFields,
    NativeProcessMessageDecryptWitness as DecryptWitness,
    NativeProcessMessageEcdhPublicFields as EcdhFields,
    NativeProcessMessageEcdhWitness as EcdhWitness,
    NativeProcessMessageSignaturePublicFields as SignatureFields,
    NativeProcessMessageSignatureWitness as SignatureWitness, process_message_coord_key_native_main,
    process_message_decrypt_native_main, process_message_ecdh_native_main,
    process_message_signature_native_main,
};
use crate::native_process_message_step_core::{
    NativeProcessMessageStepCorePublicFields as CoreFields,
    NativeProcessMessageStepCoreWitness as CoreWitness, process_message_step_core_native_main,
};
use crate::native_process_messages::{
    ProcessMessagesNativeBoundaryWitness as BoundaryWitness,
    ProcessMessagesNativePublicFields as BoundaryFields,
    ProcessMessagesNativePublicOutput as BoundaryOutput, process_messages_native_boundary_main,
};

fn verify_message_links(
    expected_index: felt252,
    boundary_fields: BoundaryFields,
    coord_fields: CoordKeyFields,
    ecdh_fields: EcdhFields,
    decrypt_fields: DecryptFields,
    signature_fields: SignatureFields,
    core_fields: CoreFields,
) {
    assert(ecdh_fields.message_index == expected_index, 'SG_ECDH_IDX');
    assert(decrypt_fields.message_index == expected_index, 'SG_DEC_IDX');
    assert(signature_fields.message_index == expected_index, 'SG_SIG_IDX');
    assert(core_fields.message_index == expected_index, 'SG_CORE_IDX');

    assert(coord_fields.coord_priv_key_hash == ecdh_fields.coord_priv_key_hash, 'SG_CK_ECDH');
    assert(coord_fields.coord_priv_key_hash == decrypt_fields.coord_priv_key_hash, 'SG_CK_DEC');
    assert(coord_fields.coord_priv_key_hash == core_fields.coord_priv_key_hash, 'SG_CK_CORE');

    assert(ecdh_fields.enc_pub_key_hash == core_fields.enc_pub_key_hash, 'SG_ECDH_ENC');
    assert(ecdh_fields.shared_key_hash == core_fields.shared_key_hash, 'SG_ECDH_SHARED');
    assert(
        ecdh_fields.shared_key_binding_hash == core_fields.shared_key_binding_hash, 'SG_ECDH_BIND',
    );

    assert(decrypt_fields.c1_hash == core_fields.state_ciphertext_c1_hash, 'SG_DEC_C1');
    assert(decrypt_fields.c2_hash == core_fields.state_ciphertext_c2_hash, 'SG_DEC_C2');
    assert(decrypt_fields.decrypt_is_odd == core_fields.state_decrypt_is_odd, 'SG_DEC_ODD');
    assert(
        decrypt_fields.decrypt_binding_hash == core_fields.state_decrypt_binding_hash,
        'SG_DEC_BIND',
    );

    assert(signature_fields.pub_key_hash == core_fields.signature_pub_key_hash, 'SG_SIG_PUB');
    assert(signature_fields.r8_hash == core_fields.signature_r8_hash, 'SG_SIG_R8');
    assert(signature_fields.packed_command_hash == core_fields.packed_command_hash, 'SG_SIG_CMD');
    assert(signature_fields.cmd_sig_s_hash == core_fields.cmd_sig_s_hash, 'SG_SIG_S');
    assert(signature_fields.command_auth_hash == core_fields.command_auth_hash, 'SG_SIG_AUTH');
    assert(signature_fields.is_signature_valid == core_fields.is_signature_valid, 'SG_SIG_VALID');

    assert(core_fields.packed_vals_hash == boundary_fields.packed_vals, 'SG_PACKED');
    assert(core_fields.expected_poll_id == boundary_fields.expected_poll_id, 'SG_POLL');
}

fn verify_head2_links(
    boundary_fields: BoundaryFields,
    boundary_witness: BoundaryWitness,
    coord_fields: CoordKeyFields,
    ecdh_0_fields: EcdhFields,
    decrypt_0_fields: DecryptFields,
    signature_0_fields: SignatureFields,
    core_0_fields: CoreFields,
    ecdh_1_fields: EcdhFields,
    decrypt_1_fields: DecryptFields,
    signature_1_fields: SignatureFields,
    core_1_fields: CoreFields,
) {
    assert(boundary_fields.coord_pub_key_hash == coord_fields.coord_pub_key_hash, 'SG_COORD');

    verify_message_links(
        0,
        boundary_fields,
        coord_fields,
        ecdh_0_fields,
        decrypt_0_fields,
        signature_0_fields,
        core_0_fields,
    );
    verify_message_links(
        1,
        boundary_fields,
        coord_fields,
        ecdh_1_fields,
        decrypt_1_fields,
        signature_1_fields,
        core_1_fields,
    );

    assert(core_0_fields.previous_message_hash == boundary_fields.batch_start_hash, 'SG_H_MSG_S');
    assert(core_0_fields.next_message_hash == core_1_fields.previous_message_hash, 'SG_H_MSG_01');
    assert(core_1_fields.next_message_hash == boundary_fields.batch_end_hash, 'SG_H_MSG_E');

    assert(
        core_1_fields.current_state_commitment_hash == boundary_fields.current_state_commitment,
        'SG_H_CUR_COM',
    );
    assert(
        core_0_fields.new_state_commitment_hash == boundary_fields.new_state_commitment,
        'SG_H_NEW_COM',
    );
    assert(
        core_1_fields.current_state_root_hash == boundary_witness.current_state_root,
        'SG_H_CUR_ROOT',
    );
    assert(core_0_fields.new_state_root_hash == boundary_witness.new_state_root, 'SG_H_NEW_ROOT');

    assert(
        core_1_fields.new_state_root_hash == core_0_fields.current_state_root_hash,
        'SG_H_STATE',
    );
    assert(
        core_0_fields.active_state_root_hash == boundary_witness.active_state_root,
        'SG_H_ACTIVE_0',
    );
    assert(
        core_0_fields.active_state_root_hash == core_1_fields.active_state_root_hash,
        'SG_H_ACTIVE_1',
    );
}

fn verify_tail3_links(
    boundary_fields: BoundaryFields,
    boundary_witness: BoundaryWitness,
    coord_fields: CoordKeyFields,
    ecdh_2_fields: EcdhFields,
    decrypt_2_fields: DecryptFields,
    signature_2_fields: SignatureFields,
    core_2_fields: CoreFields,
    ecdh_3_fields: EcdhFields,
    decrypt_3_fields: DecryptFields,
    signature_3_fields: SignatureFields,
    core_3_fields: CoreFields,
    ecdh_4_fields: EcdhFields,
    decrypt_4_fields: DecryptFields,
    signature_4_fields: SignatureFields,
    core_4_fields: CoreFields,
) {
    assert(boundary_fields.coord_pub_key_hash == coord_fields.coord_pub_key_hash, 'SG_COORD');

    verify_message_links(
        2,
        boundary_fields,
        coord_fields,
        ecdh_2_fields,
        decrypt_2_fields,
        signature_2_fields,
        core_2_fields,
    );
    verify_message_links(
        3,
        boundary_fields,
        coord_fields,
        ecdh_3_fields,
        decrypt_3_fields,
        signature_3_fields,
        core_3_fields,
    );
    verify_message_links(
        4,
        boundary_fields,
        coord_fields,
        ecdh_4_fields,
        decrypt_4_fields,
        signature_4_fields,
        core_4_fields,
    );

    assert(core_2_fields.previous_message_hash == boundary_fields.batch_start_hash, 'SG_T_MSG_S');
    assert(core_2_fields.next_message_hash == core_3_fields.previous_message_hash, 'SG_T_MSG_23');
    assert(core_3_fields.next_message_hash == core_4_fields.previous_message_hash, 'SG_T_MSG_34');
    assert(core_4_fields.next_message_hash == boundary_fields.batch_end_hash, 'SG_T_MSG_E');

    assert(
        core_4_fields.current_state_commitment_hash == boundary_fields.current_state_commitment,
        'SG_T_CUR_COM',
    );
    assert(
        core_2_fields.new_state_commitment_hash == boundary_fields.new_state_commitment,
        'SG_T_NEW_COM',
    );
    assert(
        core_4_fields.current_state_root_hash == boundary_witness.current_state_root,
        'SG_T_CUR_ROOT',
    );
    assert(core_2_fields.new_state_root_hash == boundary_witness.new_state_root, 'SG_T_NEW_ROOT');

    assert(
        core_4_fields.new_state_root_hash == core_3_fields.current_state_root_hash,
        'SG_T_STATE_43',
    );
    assert(
        core_3_fields.new_state_root_hash == core_2_fields.current_state_root_hash,
        'SG_T_STATE_32',
    );

    assert(
        core_2_fields.active_state_root_hash == boundary_witness.active_state_root,
        'SG_T_ACTIVE_2',
    );
    assert(
        core_2_fields.active_state_root_hash == core_3_fields.active_state_root_hash,
        'SG_T_ACTIVE_3',
    );
    assert(
        core_2_fields.active_state_root_hash == core_4_fields.active_state_root_hash,
        'SG_T_ACTIVE_4',
    );
}

#[executable]
pub fn process_messages_stage_segment_native_main(
    segment_kind: felt252,
    boundary_fields: BoundaryFields,
    boundary_witness: BoundaryWitness,
    coord_fields: CoordKeyFields,
    coord_witness: CoordKeyWitness,
    ecdh_0_fields: EcdhFields,
    ecdh_0_witness: EcdhWitness,
    decrypt_0_fields: DecryptFields,
    decrypt_0_witness: DecryptWitness,
    signature_0_fields: SignatureFields,
    signature_0_witness: SignatureWitness,
    core_0_fields: CoreFields,
    core_0_witness: CoreWitness,
    ecdh_1_fields: EcdhFields,
    ecdh_1_witness: EcdhWitness,
    decrypt_1_fields: DecryptFields,
    decrypt_1_witness: DecryptWitness,
    signature_1_fields: SignatureFields,
    signature_1_witness: SignatureWitness,
    core_1_fields: CoreFields,
    core_1_witness: CoreWitness,
    ecdh_2_fields: EcdhFields,
    ecdh_2_witness: EcdhWitness,
    decrypt_2_fields: DecryptFields,
    decrypt_2_witness: DecryptWitness,
    signature_2_fields: SignatureFields,
    signature_2_witness: SignatureWitness,
    core_2_fields: CoreFields,
    core_2_witness: CoreWitness,
) -> BoundaryOutput {
    assert(segment_kind == 2 || segment_kind == 3, 'SG_BAD_KIND');

    let _coord_output = process_message_coord_key_native_main(coord_fields, coord_witness);

    let _ecdh_0_output = process_message_ecdh_native_main(ecdh_0_fields, ecdh_0_witness);
    let _decrypt_0_output = process_message_decrypt_native_main(
        decrypt_0_fields, decrypt_0_witness,
    );
    let _signature_0_output = process_message_signature_native_main(
        signature_0_fields, signature_0_witness,
    );
    let _core_0_output = process_message_step_core_native_main(core_0_fields, core_0_witness);

    let _ecdh_1_output = process_message_ecdh_native_main(ecdh_1_fields, ecdh_1_witness);
    let _decrypt_1_output = process_message_decrypt_native_main(
        decrypt_1_fields, decrypt_1_witness,
    );
    let _signature_1_output = process_message_signature_native_main(
        signature_1_fields, signature_1_witness,
    );
    let _core_1_output = process_message_step_core_native_main(core_1_fields, core_1_witness);

    if segment_kind == 2 {
        verify_head2_links(
            boundary_fields,
            boundary_witness,
            coord_fields,
            ecdh_0_fields,
            decrypt_0_fields,
            signature_0_fields,
            core_0_fields,
            ecdh_1_fields,
            decrypt_1_fields,
            signature_1_fields,
            core_1_fields,
        );
    } else {
        let _ecdh_2_output = process_message_ecdh_native_main(ecdh_2_fields, ecdh_2_witness);
        let _decrypt_2_output = process_message_decrypt_native_main(
            decrypt_2_fields, decrypt_2_witness,
        );
        let _signature_2_output = process_message_signature_native_main(
            signature_2_fields, signature_2_witness,
        );
        let _core_2_output = process_message_step_core_native_main(core_2_fields, core_2_witness);

        verify_tail3_links(
            boundary_fields,
            boundary_witness,
            coord_fields,
            ecdh_0_fields,
            decrypt_0_fields,
            signature_0_fields,
            core_0_fields,
            ecdh_1_fields,
            decrypt_1_fields,
            signature_1_fields,
            core_1_fields,
            ecdh_2_fields,
            decrypt_2_fields,
            signature_2_fields,
            core_2_fields,
        );
    };

    process_messages_native_boundary_main(boundary_fields, boundary_witness)
}
