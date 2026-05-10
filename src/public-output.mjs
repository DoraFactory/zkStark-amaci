import {
  ADD_NEW_KEY_CIRCUIT_ID,
  PROCESS_DEACTIVATE_COORD_KEY_CIRCUIT_ID,
  PROCESS_DEACTIVATE_CIRCUIT_ID,
  PROCESS_DEACTIVATE_DECRYPT_CIRCUIT_ID,
  PROCESS_DEACTIVATE_ECDH_CIRCUIT_ID,
  PROCESS_DEACTIVATE_SIGNATURE_CIRCUIT_ID,
  PROCESS_DEACTIVATE_STEP_CIRCUIT_ID,
  PROCESS_DEACTIVATE_STEP_CORE_CIRCUIT_ID,
  PROCESS_MESSAGE_COORD_KEY_CIRCUIT_ID,
  PROCESS_MESSAGE_ECDH_CIRCUIT_ID,
  PROCESS_MESSAGE_SIGNATURE_CIRCUIT_ID,
  PROCESS_MESSAGE_STEP_CIRCUIT_ID,
  PROCESS_MESSAGE_STEP_CORE_CIRCUIT_ID,
  PROCESS_MESSAGES_CIRCUIT_ID,
  PUBLIC_OUTPUT_MAGIC,
  PUBLIC_OUTPUT_VERSION,
  SMALL_PROCESS_DEACTIVATE_PARAMS,
  SMALL_PROCESS_MESSAGES_PARAMS,
  SMALL_TALLY_PARAMS,
  TALLY_VOTES_CIRCUIT_ID,
} from './constants.mjs';
import { decimalize, splitU256ToU128 } from './compat/encoding.mjs';

function pushU256(output, labels, name, value) {
  const { low, high } = splitU256ToU128(value, name);
  labels.push(`${name}_low128`, `${name}_high128`);
  output.push(low, high);
}

export function canonicalTallyPublicOutput(fields, params = SMALL_TALLY_PARAMS) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'int_state_tree_depth',
    'vote_option_tree_depth',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    TALLY_VOTES_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.intStateTreeDepth),
    BigInt(params.voteOptionTreeDepth),
  ];

  pushU256(output, labels, 'packed_vals', fields.packedVals);
  pushU256(output, labels, 'state_commitment', fields.stateCommitment);
  pushU256(output, labels, 'current_tally_commitment', fields.currentTallyCommitment);
  pushU256(output, labels, 'new_tally_commitment', fields.newTallyCommitment);
  pushU256(output, labels, 'input_hash', fields.inputHash);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessMessagesPublicOutput(
  fields,
  params = SMALL_PROCESS_MESSAGES_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'vote_option_tree_depth',
    'message_batch_size',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_MESSAGES_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.voteOptionTreeDepth),
    BigInt(params.messageBatchSize),
  ];

  pushU256(output, labels, 'packed_vals', fields.packedVals);
  pushU256(output, labels, 'coord_pub_key_hash', fields.coordPubKeyHash);
  pushU256(output, labels, 'batch_start_hash', fields.batchStartHash);
  pushU256(output, labels, 'batch_end_hash', fields.batchEndHash);
  pushU256(output, labels, 'current_state_commitment', fields.currentStateCommitment);
  pushU256(output, labels, 'new_state_commitment', fields.newStateCommitment);
  pushU256(output, labels, 'deactivate_commitment', fields.deactivateCommitment);
  pushU256(output, labels, 'expected_poll_id', fields.expectedPollId);
  pushU256(output, labels, 'input_hash', fields.inputHash);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessMessageStepPublicOutput(
  fields,
  params = SMALL_PROCESS_MESSAGES_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'vote_option_tree_depth',
    'message_batch_size',
    'message_index',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_MESSAGE_STEP_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.voteOptionTreeDepth),
    BigInt(params.messageBatchSize),
    BigInt(fields.messageIndex),
  ];

  pushU256(output, labels, 'packed_vals', fields.packedVals);
  pushU256(output, labels, 'coord_pub_key_hash', fields.coordPubKeyHash);
  pushU256(output, labels, 'previous_message_hash', fields.previousMessageHash);
  pushU256(output, labels, 'next_message_hash', fields.nextMessageHash);
  pushU256(output, labels, 'current_state_root', fields.currentStateRoot);
  pushU256(output, labels, 'new_state_root', fields.newStateRoot);
  pushU256(output, labels, 'current_state_commitment', fields.currentStateCommitment);
  pushU256(output, labels, 'new_state_commitment', fields.newStateCommitment);
  pushU256(output, labels, 'active_state_root', fields.activeStateRoot);
  pushU256(output, labels, 'expected_poll_id', fields.expectedPollId);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessMessageCoordKeyPublicOutput(
  fields,
  params = SMALL_PROCESS_MESSAGES_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'vote_option_tree_depth',
    'message_batch_size',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_MESSAGE_COORD_KEY_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.voteOptionTreeDepth),
    BigInt(params.messageBatchSize),
  ];

  pushU256(output, labels, 'coord_pub_key_hash', fields.coordPubKeyHash);
  pushU256(output, labels, 'coord_priv_key_hash', fields.coordPrivKeyHash);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessMessageEcdhPublicOutput(
  fields,
  params = SMALL_PROCESS_MESSAGES_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'vote_option_tree_depth',
    'message_batch_size',
    'message_index',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_MESSAGE_ECDH_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.voteOptionTreeDepth),
    BigInt(params.messageBatchSize),
    BigInt(fields.messageIndex),
  ];

  pushU256(output, labels, 'coord_priv_key_hash', fields.coordPrivKeyHash);
  pushU256(output, labels, 'enc_pub_key_hash', fields.encPubKeyHash);
  pushU256(output, labels, 'shared_key_hash', fields.sharedKeyHash);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessMessageSignaturePublicOutput(
  fields,
  params = SMALL_PROCESS_MESSAGES_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'vote_option_tree_depth',
    'message_batch_size',
    'message_index',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_MESSAGE_SIGNATURE_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.voteOptionTreeDepth),
    BigInt(params.messageBatchSize),
    BigInt(fields.messageIndex),
  ];

  pushU256(output, labels, 'pub_key_hash', fields.pubKeyHash);
  pushU256(output, labels, 'r8_hash', fields.r8Hash);
  pushU256(output, labels, 'packed_command_hash', fields.packedCommandHash);
  pushU256(output, labels, 'cmd_sig_s', fields.cmdSigS);
  pushU256(output, labels, 'is_signature_valid', fields.isSignatureValid);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessMessageStepCorePublicOutput(
  fields,
  params = SMALL_PROCESS_MESSAGES_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'vote_option_tree_depth',
    'message_batch_size',
    'message_index',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_MESSAGE_STEP_CORE_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.voteOptionTreeDepth),
    BigInt(params.messageBatchSize),
    BigInt(fields.messageIndex),
  ];

  pushU256(output, labels, 'packed_vals', fields.packedVals);
  pushU256(output, labels, 'coord_pub_key_hash', fields.coordPubKeyHash);
  pushU256(output, labels, 'coord_priv_key_hash', fields.coordPrivKeyHash);
  pushU256(output, labels, 'previous_message_hash', fields.previousMessageHash);
  pushU256(output, labels, 'next_message_hash', fields.nextMessageHash);
  pushU256(output, labels, 'current_state_root', fields.currentStateRoot);
  pushU256(output, labels, 'new_state_root', fields.newStateRoot);
  pushU256(output, labels, 'current_state_commitment', fields.currentStateCommitment);
  pushU256(output, labels, 'new_state_commitment', fields.newStateCommitment);
  pushU256(output, labels, 'active_state_root', fields.activeStateRoot);
  pushU256(output, labels, 'expected_poll_id', fields.expectedPollId);
  pushU256(output, labels, 'enc_pub_key_hash', fields.encPubKeyHash);
  pushU256(output, labels, 'shared_key_hash', fields.sharedKeyHash);
  pushU256(output, labels, 'signature_pub_key_hash', fields.signaturePubKeyHash);
  pushU256(output, labels, 'signature_r8_hash', fields.signatureR8Hash);
  pushU256(output, labels, 'packed_command_hash', fields.packedCommandHash);
  pushU256(output, labels, 'cmd_sig_s', fields.cmdSigS);
  pushU256(output, labels, 'is_signature_valid', fields.isSignatureValid);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalAddNewKeyPublicOutput(fields, params = { stateTreeDepth: 2 }) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'deactivate_tree_depth',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    ADD_NEW_KEY_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.stateTreeDepth + 2),
  ];

  pushU256(output, labels, 'deactivate_root', fields.deactivateRoot);
  pushU256(output, labels, 'coord_pub_key_hash', fields.coordPubKeyHash);
  pushU256(output, labels, 'nullifier', fields.nullifier);
  pushU256(output, labels, 'd1_x', fields.d1[0]);
  pushU256(output, labels, 'd1_y', fields.d1[1]);
  pushU256(output, labels, 'd2_x', fields.d2[0]);
  pushU256(output, labels, 'd2_y', fields.d2[1]);
  pushU256(output, labels, 'new_pub_key_hash', fields.newPubKeyHash);
  pushU256(output, labels, 'poll_id', fields.pollId);
  pushU256(output, labels, 'input_hash', fields.inputHash);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessDeactivatePublicOutput(
  fields,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'deactivate_tree_depth',
    'message_batch_size',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_DEACTIVATE_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.deactivateTreeDepth),
    BigInt(params.messageBatchSize),
  ];

  pushU256(output, labels, 'new_deactivate_root', fields.newDeactivateRoot);
  pushU256(output, labels, 'coord_pub_key_hash', fields.coordPubKeyHash);
  pushU256(output, labels, 'batch_start_hash', fields.batchStartHash);
  pushU256(output, labels, 'batch_end_hash', fields.batchEndHash);
  pushU256(output, labels, 'current_deactivate_commitment', fields.currentDeactivateCommitment);
  pushU256(output, labels, 'new_deactivate_commitment', fields.newDeactivateCommitment);
  pushU256(output, labels, 'current_state_root', fields.currentStateRoot);
  pushU256(output, labels, 'expected_poll_id', fields.expectedPollId);
  pushU256(output, labels, 'input_hash', fields.inputHash);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessDeactivateStepPublicOutput(
  fields,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'deactivate_tree_depth',
    'message_batch_size',
    'message_index',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_DEACTIVATE_STEP_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.deactivateTreeDepth),
    BigInt(params.messageBatchSize),
    BigInt(fields.messageIndex),
  ];

  pushU256(output, labels, 'deactivate_index', fields.deactivateIndex);
  pushU256(output, labels, 'coord_pub_key_hash', fields.coordPubKeyHash);
  pushU256(output, labels, 'previous_message_hash', fields.previousMessageHash);
  pushU256(output, labels, 'next_message_hash', fields.nextMessageHash);
  pushU256(output, labels, 'current_active_state_root', fields.currentActiveStateRoot);
  pushU256(output, labels, 'current_deactivate_root', fields.currentDeactivateRoot);
  pushU256(output, labels, 'new_active_state_root', fields.newActiveStateRoot);
  pushU256(output, labels, 'new_deactivate_root', fields.newDeactivateRoot);
  pushU256(output, labels, 'current_deactivate_commitment', fields.currentDeactivateCommitment);
  pushU256(output, labels, 'new_deactivate_commitment', fields.newDeactivateCommitment);
  pushU256(output, labels, 'current_state_root', fields.currentStateRoot);
  pushU256(output, labels, 'expected_poll_id', fields.expectedPollId);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessDeactivateCoordKeyPublicOutput(
  fields,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'deactivate_tree_depth',
    'message_batch_size',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_DEACTIVATE_COORD_KEY_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.deactivateTreeDepth),
    BigInt(params.messageBatchSize),
  ];

  pushU256(output, labels, 'coord_pub_key_hash', fields.coordPubKeyHash);
  pushU256(output, labels, 'coord_priv_key_hash', fields.coordPrivKeyHash);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessDeactivateEcdhPublicOutput(
  fields,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'deactivate_tree_depth',
    'message_batch_size',
    'message_index',
    'ecdh_kind',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_DEACTIVATE_ECDH_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.deactivateTreeDepth),
    BigInt(params.messageBatchSize),
    BigInt(fields.messageIndex),
    BigInt(fields.ecdhKind),
  ];

  pushU256(output, labels, 'coord_priv_key_hash', fields.coordPrivKeyHash);
  pushU256(output, labels, 'base_hash', fields.baseHash);
  pushU256(output, labels, 'shared_key_hash', fields.sharedKeyHash);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessDeactivateSignaturePublicOutput(
  fields,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'deactivate_tree_depth',
    'message_batch_size',
    'message_index',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_DEACTIVATE_SIGNATURE_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.deactivateTreeDepth),
    BigInt(params.messageBatchSize),
    BigInt(fields.messageIndex),
  ];

  pushU256(output, labels, 'pub_key_hash', fields.pubKeyHash);
  pushU256(output, labels, 'r8_hash', fields.r8Hash);
  pushU256(output, labels, 'packed_cmd_hash', fields.packedCmdHash);
  pushU256(output, labels, 'cmd_sig_s', fields.cmdSigS);
  pushU256(output, labels, 'signature_valid', fields.signatureValid);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessDeactivateDecryptPublicOutput(
  fields,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'deactivate_tree_depth',
    'message_batch_size',
    'message_index',
    'decrypt_kind',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_DEACTIVATE_DECRYPT_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.deactivateTreeDepth),
    BigInt(params.messageBatchSize),
    BigInt(fields.messageIndex),
    BigInt(fields.decryptKind),
  ];

  pushU256(output, labels, 'coord_priv_key_hash', fields.coordPrivKeyHash);
  pushU256(output, labels, 'c1_hash', fields.c1Hash);
  pushU256(output, labels, 'c2_hash', fields.c2Hash);
  pushU256(output, labels, 'decrypt_is_odd', fields.decryptIsOdd);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

export function canonicalProcessDeactivateStepCorePublicOutput(
  fields,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'deactivate_tree_depth',
    'message_batch_size',
    'message_index',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    PROCESS_DEACTIVATE_STEP_CORE_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.deactivateTreeDepth),
    BigInt(params.messageBatchSize),
    BigInt(fields.messageIndex),
  ];

  pushU256(output, labels, 'deactivate_index', fields.deactivateIndex);
  pushU256(output, labels, 'coord_pub_key_hash', fields.coordPubKeyHash);
  pushU256(output, labels, 'coord_priv_key_hash', fields.coordPrivKeyHash);
  pushU256(output, labels, 'previous_message_hash', fields.previousMessageHash);
  pushU256(output, labels, 'next_message_hash', fields.nextMessageHash);
  pushU256(output, labels, 'current_active_state_root', fields.currentActiveStateRoot);
  pushU256(output, labels, 'current_deactivate_root', fields.currentDeactivateRoot);
  pushU256(output, labels, 'new_active_state_root', fields.newActiveStateRoot);
  pushU256(output, labels, 'new_deactivate_root', fields.newDeactivateRoot);
  pushU256(output, labels, 'current_deactivate_commitment', fields.currentDeactivateCommitment);
  pushU256(output, labels, 'new_deactivate_commitment', fields.newDeactivateCommitment);
  pushU256(output, labels, 'current_state_root', fields.currentStateRoot);
  pushU256(output, labels, 'expected_poll_id', fields.expectedPollId);
  pushU256(output, labels, 'enc_pub_key_hash', fields.encPubKeyHash);
  pushU256(output, labels, 'command_shared_key_hash', fields.commandSharedKeyHash);
  pushU256(output, labels, 'signature_pub_key_hash', fields.signaturePubKeyHash);
  pushU256(output, labels, 'signature_r8_hash', fields.signatureR8Hash);
  pushU256(output, labels, 'packed_cmd_hash', fields.packedCmdHash);
  pushU256(output, labels, 'cmd_sig_s', fields.cmdSigS);
  pushU256(output, labels, 'signature_valid', fields.signatureValid);
  pushU256(output, labels, 'current_state_ciphertext_c1_hash', fields.currentStateCiphertextC1Hash);
  pushU256(output, labels, 'current_state_ciphertext_c2_hash', fields.currentStateCiphertextC2Hash);
  pushU256(output, labels, 'current_decrypt_is_odd', fields.currentDecryptIsOdd);
  pushU256(output, labels, 'new_state_ciphertext_c1_hash', fields.newStateCiphertextC1Hash);
  pushU256(output, labels, 'new_state_ciphertext_c2_hash', fields.newStateCiphertextC2Hash);
  pushU256(output, labels, 'new_decrypt_is_odd', fields.newDecryptIsOdd);
  pushU256(output, labels, 'deactivate_pub_key_hash', fields.deactivatePubKeyHash);
  pushU256(output, labels, 'deactivate_shared_key_hash', fields.deactivateSharedKeyHash);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}
