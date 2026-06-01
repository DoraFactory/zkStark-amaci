use crate::native_process_deactivate::{
    ProcessDeactivateNativeBoundaryWitness as BoundaryWitness,
    ProcessDeactivateNativePublicFields as BoundaryFields,
    ProcessDeactivateNativePublicOutput as BoundaryOutput, process_deactivate_native_boundary_main,
};
use crate::native_process_deactivate_components::{
    NativeProcessDeactivateCoordKeyPublicFields as CoordKeyFields,
    NativeProcessDeactivateCoordKeyWitness as CoordKeyWitness,
    NativeProcessDeactivateDecryptPublicFields as DecryptFields,
    NativeProcessDeactivateDecryptWitness as DecryptWitness,
    NativeProcessDeactivateEcdhPublicFields as EcdhFields,
    NativeProcessDeactivateEcdhWitness as EcdhWitness,
    NativeProcessDeactivateSignaturePublicFields as SignatureFields,
    NativeProcessDeactivateSignatureWitness as SignatureWitness,
    process_deactivate_coord_key_native_main, process_deactivate_decrypt_native_main,
    process_deactivate_ecdh_native_main, process_deactivate_signature_native_main,
};
use crate::native_process_deactivate_step_core::{
    NativeProcessDeactivateStepCorePublicFields as CoreFields,
    NativeProcessDeactivateStepCoreWitness as CoreWitness, process_deactivate_step_core_native_main,
};

fn verify_deactivate_message_links(
    expected_index: felt252,
    boundary_fields: BoundaryFields,
    coord_fields: CoordKeyFields,
    command_ecdh_fields: EcdhFields,
    leaf_ecdh_fields: EcdhFields,
    signature_fields: SignatureFields,
    current_decrypt_fields: DecryptFields,
    new_decrypt_fields: DecryptFields,
    core_fields: CoreFields,
) {
    assert(command_ecdh_fields.message_index == expected_index, 'D_CMD_ECDH_IDX');
    assert(leaf_ecdh_fields.message_index == expected_index, 'D_LEAF_ECDH_IDX');
    assert(signature_fields.message_index == expected_index, 'D_SIG_IDX');
    assert(current_decrypt_fields.message_index == expected_index, 'D_CUR_DEC_IDX');
    assert(new_decrypt_fields.message_index == expected_index, 'D_NEW_DEC_IDX');
    assert(core_fields.message_index == expected_index, 'D_CORE_IDX');

    assert(command_ecdh_fields.ecdh_kind == 0, 'D_CMD_ECDH_KIND');
    assert(leaf_ecdh_fields.ecdh_kind == 1, 'D_LEAF_ECDH_KIND');
    assert(current_decrypt_fields.decrypt_kind == 0, 'D_CUR_DEC_KIND');
    assert(new_decrypt_fields.decrypt_kind == 1, 'D_NEW_DEC_KIND');

    assert(
        coord_fields.coord_priv_key_hash == command_ecdh_fields.coord_priv_key_hash,
        'D_CK_CMD_ECDH',
    );
    assert(
        coord_fields.coord_priv_key_hash == leaf_ecdh_fields.coord_priv_key_hash, 'D_CK_LEAF_ECDH',
    );
    assert(
        coord_fields.coord_priv_key_hash == current_decrypt_fields.coord_priv_key_hash,
        'D_CK_CUR_DEC',
    );
    assert(
        coord_fields.coord_priv_key_hash == new_decrypt_fields.coord_priv_key_hash, 'D_CK_NEW_DEC',
    );
    assert(coord_fields.coord_priv_key_hash == core_fields.coord_priv_key_hash, 'D_CK_CORE');

    assert(command_ecdh_fields.base_hash == core_fields.enc_pub_key_hash, 'D_CMD_BASE');
    assert(
        command_ecdh_fields.shared_key_hash == core_fields.command_shared_key_hash, 'D_CMD_SHARED',
    );
    assert(
        command_ecdh_fields.shared_key_binding_hash == core_fields.command_shared_key_binding_hash,
        'D_CMD_BIND',
    );
    assert(leaf_ecdh_fields.base_hash == core_fields.deactivate_pub_key_hash, 'D_LEAF_BASE');
    assert(
        leaf_ecdh_fields.shared_key_hash == core_fields.deactivate_shared_key_hash, 'D_LEAF_SHARED',
    );
    assert(
        leaf_ecdh_fields.shared_key_binding_hash == core_fields.deactivate_shared_key_binding_hash,
        'D_LEAF_BIND',
    );

    assert(signature_fields.pub_key_hash == core_fields.signature_pub_key_hash, 'D_SIG_PUB');
    assert(signature_fields.r8_hash == core_fields.signature_r8_hash, 'D_SIG_R8');
    assert(signature_fields.packed_cmd_hash == core_fields.packed_cmd_hash, 'D_SIG_CMD');
    assert(signature_fields.cmd_sig_s_hash == core_fields.cmd_sig_s_hash, 'D_SIG_S');
    assert(signature_fields.command_auth_hash == core_fields.command_auth_hash, 'D_SIG_AUTH');
    assert(signature_fields.signature_valid == core_fields.signature_valid, 'D_SIG_VALID');

    assert(
        current_decrypt_fields.c1_hash == core_fields.current_state_ciphertext_c1_hash, 'D_CUR_C1',
    );
    assert(
        current_decrypt_fields.c2_hash == core_fields.current_state_ciphertext_c2_hash, 'D_CUR_C2',
    );
    assert(
        current_decrypt_fields.decrypt_is_odd == core_fields.current_decrypt_is_odd, 'D_CUR_ODD',
    );
    assert(
        current_decrypt_fields.decrypt_binding_hash == core_fields.current_decrypt_binding_hash,
        'D_CUR_BIND',
    );
    assert(new_decrypt_fields.c1_hash == core_fields.new_state_ciphertext_c1_hash, 'D_NEW_C1');
    assert(new_decrypt_fields.c2_hash == core_fields.new_state_ciphertext_c2_hash, 'D_NEW_C2');
    assert(new_decrypt_fields.decrypt_is_odd == core_fields.new_decrypt_is_odd, 'D_NEW_ODD');
    assert(
        new_decrypt_fields.decrypt_binding_hash == core_fields.new_decrypt_binding_hash,
        'D_NEW_BIND',
    );

    assert(core_fields.current_state_root_hash == boundary_fields.current_state_root, 'D_STATE');
    assert(core_fields.expected_poll_id == boundary_fields.expected_poll_id, 'D_POLL');
}

fn verify_stage_links(
    boundary_fields: BoundaryFields,
    boundary_witness: BoundaryWitness,
    coord_fields: CoordKeyFields,
    command_ecdh_0_fields: EcdhFields,
    leaf_ecdh_0_fields: EcdhFields,
    signature_0_fields: SignatureFields,
    current_decrypt_0_fields: DecryptFields,
    new_decrypt_0_fields: DecryptFields,
    core_0_fields: CoreFields,
    command_ecdh_1_fields: EcdhFields,
    leaf_ecdh_1_fields: EcdhFields,
    signature_1_fields: SignatureFields,
    current_decrypt_1_fields: DecryptFields,
    new_decrypt_1_fields: DecryptFields,
    core_1_fields: CoreFields,
    command_ecdh_2_fields: EcdhFields,
    leaf_ecdh_2_fields: EcdhFields,
    signature_2_fields: SignatureFields,
    current_decrypt_2_fields: DecryptFields,
    new_decrypt_2_fields: DecryptFields,
    core_2_fields: CoreFields,
) {
    assert(boundary_fields.coord_pub_key_hash == coord_fields.coord_pub_key_hash, 'D_COORD');

    verify_deactivate_message_links(
        0,
        boundary_fields,
        coord_fields,
        command_ecdh_0_fields,
        leaf_ecdh_0_fields,
        signature_0_fields,
        current_decrypt_0_fields,
        new_decrypt_0_fields,
        core_0_fields,
    );
    verify_deactivate_message_links(
        1,
        boundary_fields,
        coord_fields,
        command_ecdh_1_fields,
        leaf_ecdh_1_fields,
        signature_1_fields,
        current_decrypt_1_fields,
        new_decrypt_1_fields,
        core_1_fields,
    );
    verify_deactivate_message_links(
        2,
        boundary_fields,
        coord_fields,
        command_ecdh_2_fields,
        leaf_ecdh_2_fields,
        signature_2_fields,
        current_decrypt_2_fields,
        new_decrypt_2_fields,
        core_2_fields,
    );

    assert(core_0_fields.previous_message_hash == boundary_fields.batch_start_hash, 'D_MSG_START');
    assert(core_0_fields.next_message_hash == core_1_fields.previous_message_hash, 'D_MSG_01');
    assert(core_1_fields.next_message_hash == core_2_fields.previous_message_hash, 'D_MSG_12');
    assert(core_2_fields.next_message_hash == boundary_fields.batch_end_hash, 'D_MSG_END');

    assert(
        core_0_fields
            .current_deactivate_commitment_hash == boundary_fields
            .current_deactivate_commitment,
        'D_CUR_COM',
    );
    assert(
        core_2_fields.new_deactivate_commitment_hash == boundary_fields.new_deactivate_commitment,
        'D_NEW_COM',
    );
    assert(
        core_2_fields.new_deactivate_root_hash == boundary_fields.new_deactivate_root,
        'D_NEW_DEACT_ROOT',
    );
    assert(
        core_0_fields.current_active_state_root_hash == boundary_witness.current_active_state_root,
        'D_CUR_ACTIVE',
    );
    assert(
        core_0_fields.current_deactivate_root_hash == boundary_witness.current_deactivate_root,
        'D_CUR_DEACT',
    );
    assert(
        core_2_fields.new_active_state_root_hash == boundary_witness.new_active_state_root,
        'D_NEW_ACTIVE',
    );

    assert(
        core_0_fields.new_active_state_root_hash == core_1_fields.current_active_state_root_hash,
        'D_ACTIVE_01',
    );
    assert(
        core_1_fields.new_active_state_root_hash == core_2_fields.current_active_state_root_hash,
        'D_ACTIVE_12',
    );
    assert(
        core_0_fields.new_deactivate_root_hash == core_1_fields.current_deactivate_root_hash,
        'D_DEACT_01',
    );
    assert(
        core_1_fields.new_deactivate_root_hash == core_2_fields.current_deactivate_root_hash,
        'D_DEACT_12',
    );
    assert(
        core_0_fields
            .new_deactivate_commitment_hash == core_1_fields
            .current_deactivate_commitment_hash,
        'D_COM_01',
    );
    assert(
        core_1_fields
            .new_deactivate_commitment_hash == core_2_fields
            .current_deactivate_commitment_hash,
        'D_COM_12',
    );
}

#[executable]
pub fn process_deactivate_stage_native_main(
    boundary_fields: BoundaryFields,
    boundary_witness: BoundaryWitness,
    coord_fields: CoordKeyFields,
    coord_witness: CoordKeyWitness,
    command_ecdh_0_fields: EcdhFields,
    command_ecdh_0_witness: EcdhWitness,
    leaf_ecdh_0_fields: EcdhFields,
    leaf_ecdh_0_witness: EcdhWitness,
    signature_0_fields: SignatureFields,
    signature_0_witness: SignatureWitness,
    current_decrypt_0_fields: DecryptFields,
    current_decrypt_0_witness: DecryptWitness,
    new_decrypt_0_fields: DecryptFields,
    new_decrypt_0_witness: DecryptWitness,
    core_0_fields: CoreFields,
    core_0_witness: CoreWitness,
    command_ecdh_1_fields: EcdhFields,
    command_ecdh_1_witness: EcdhWitness,
    leaf_ecdh_1_fields: EcdhFields,
    leaf_ecdh_1_witness: EcdhWitness,
    signature_1_fields: SignatureFields,
    signature_1_witness: SignatureWitness,
    current_decrypt_1_fields: DecryptFields,
    current_decrypt_1_witness: DecryptWitness,
    new_decrypt_1_fields: DecryptFields,
    new_decrypt_1_witness: DecryptWitness,
    core_1_fields: CoreFields,
    core_1_witness: CoreWitness,
    command_ecdh_2_fields: EcdhFields,
    command_ecdh_2_witness: EcdhWitness,
    leaf_ecdh_2_fields: EcdhFields,
    leaf_ecdh_2_witness: EcdhWitness,
    signature_2_fields: SignatureFields,
    signature_2_witness: SignatureWitness,
    current_decrypt_2_fields: DecryptFields,
    current_decrypt_2_witness: DecryptWitness,
    new_decrypt_2_fields: DecryptFields,
    new_decrypt_2_witness: DecryptWitness,
    core_2_fields: CoreFields,
    core_2_witness: CoreWitness,
) -> BoundaryOutput {
    let _coord_output = process_deactivate_coord_key_native_main(coord_fields, coord_witness);

    let _command_ecdh_0_output = process_deactivate_ecdh_native_main(
        command_ecdh_0_fields, command_ecdh_0_witness,
    );
    let _leaf_ecdh_0_output = process_deactivate_ecdh_native_main(
        leaf_ecdh_0_fields, leaf_ecdh_0_witness,
    );
    let _signature_0_output = process_deactivate_signature_native_main(
        signature_0_fields, signature_0_witness,
    );
    let _current_decrypt_0_output = process_deactivate_decrypt_native_main(
        current_decrypt_0_fields, current_decrypt_0_witness,
    );
    let _new_decrypt_0_output = process_deactivate_decrypt_native_main(
        new_decrypt_0_fields, new_decrypt_0_witness,
    );
    let _core_0_output = process_deactivate_step_core_native_main(core_0_fields, core_0_witness);

    let _command_ecdh_1_output = process_deactivate_ecdh_native_main(
        command_ecdh_1_fields, command_ecdh_1_witness,
    );
    let _leaf_ecdh_1_output = process_deactivate_ecdh_native_main(
        leaf_ecdh_1_fields, leaf_ecdh_1_witness,
    );
    let _signature_1_output = process_deactivate_signature_native_main(
        signature_1_fields, signature_1_witness,
    );
    let _current_decrypt_1_output = process_deactivate_decrypt_native_main(
        current_decrypt_1_fields, current_decrypt_1_witness,
    );
    let _new_decrypt_1_output = process_deactivate_decrypt_native_main(
        new_decrypt_1_fields, new_decrypt_1_witness,
    );
    let _core_1_output = process_deactivate_step_core_native_main(core_1_fields, core_1_witness);

    let _command_ecdh_2_output = process_deactivate_ecdh_native_main(
        command_ecdh_2_fields, command_ecdh_2_witness,
    );
    let _leaf_ecdh_2_output = process_deactivate_ecdh_native_main(
        leaf_ecdh_2_fields, leaf_ecdh_2_witness,
    );
    let _signature_2_output = process_deactivate_signature_native_main(
        signature_2_fields, signature_2_witness,
    );
    let _current_decrypt_2_output = process_deactivate_decrypt_native_main(
        current_decrypt_2_fields, current_decrypt_2_witness,
    );
    let _new_decrypt_2_output = process_deactivate_decrypt_native_main(
        new_decrypt_2_fields, new_decrypt_2_witness,
    );
    let _core_2_output = process_deactivate_step_core_native_main(core_2_fields, core_2_witness);

    verify_stage_links(
        boundary_fields,
        boundary_witness,
        coord_fields,
        command_ecdh_0_fields,
        leaf_ecdh_0_fields,
        signature_0_fields,
        current_decrypt_0_fields,
        new_decrypt_0_fields,
        core_0_fields,
        command_ecdh_1_fields,
        leaf_ecdh_1_fields,
        signature_1_fields,
        current_decrypt_1_fields,
        new_decrypt_1_fields,
        core_1_fields,
        command_ecdh_2_fields,
        leaf_ecdh_2_fields,
        signature_2_fields,
        current_decrypt_2_fields,
        new_decrypt_2_fields,
        core_2_fields,
    );

    process_deactivate_native_boundary_main(boundary_fields, boundary_witness)
}
