import {
  ADD_NEW_KEY_NATIVE_CIRCUIT_ID,
  NATIVE_PUBLIC_OUTPUT_VERSION,
  PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID,
  PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
  PUBLIC_OUTPUT_MAGIC,
  SMALL_PROCESS_DEACTIVATE_PARAMS,
  SMALL_PROCESS_MESSAGES_PARAMS,
  SMALL_TALLY_PARAMS,
  STARKNET_POSEIDON_HASH_SCHEME,
  TALLY_VOTES_NATIVE_CIRCUIT_ID,
} from './constants.mjs';
import { decimalize } from './encoding.mjs';

function publicOutput(labels, felts) {
  return {
    labels,
    felts,
    decimalFelts: felts.map(decimalize),
  };
}

export function canonicalNativeTallyPublicOutput(fields, params = SMALL_TALLY_PARAMS) {
  return publicOutput(
    [
      'magic',
      'version',
      'circuit_id',
      'hash_scheme',
      'state_tree_depth',
      'int_state_tree_depth',
      'vote_option_tree_depth',
      'packed_vals',
      'state_commitment',
      'current_tally_commitment',
      'new_tally_commitment',
      'input_hash',
    ],
    [
      PUBLIC_OUTPUT_MAGIC,
      NATIVE_PUBLIC_OUTPUT_VERSION,
      TALLY_VOTES_NATIVE_CIRCUIT_ID,
      STARKNET_POSEIDON_HASH_SCHEME,
      BigInt(params.stateTreeDepth),
      BigInt(params.intStateTreeDepth),
      BigInt(params.voteOptionTreeDepth),
      fields.packedVals,
      fields.stateCommitment,
      fields.currentTallyCommitment,
      fields.newTallyCommitment,
      fields.inputHash,
    ],
  );
}

export function canonicalNativeProcessMessagesPublicOutput(
  fields,
  params = SMALL_PROCESS_MESSAGES_PARAMS,
) {
  return publicOutput(
    [
      'magic',
      'version',
      'circuit_id',
      'hash_scheme',
      'state_tree_depth',
      'vote_option_tree_depth',
      'message_batch_size',
      'packed_vals',
      'coord_pub_key_hash',
      'batch_start_hash',
      'batch_end_hash',
      'current_state_commitment',
      'new_state_commitment',
      'deactivate_commitment',
      'expected_poll_id',
      'input_hash',
    ],
    [
      PUBLIC_OUTPUT_MAGIC,
      NATIVE_PUBLIC_OUTPUT_VERSION,
      PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
      STARKNET_POSEIDON_HASH_SCHEME,
      BigInt(params.stateTreeDepth),
      BigInt(params.voteOptionTreeDepth),
      BigInt(params.messageBatchSize),
      fields.packedVals,
      fields.coordPubKeyHash,
      fields.batchStartHash,
      fields.batchEndHash,
      fields.currentStateCommitment,
      fields.newStateCommitment,
      fields.deactivateCommitment,
      fields.expectedPollId,
      fields.inputHash,
    ],
  );
}

export function canonicalNativeAddNewKeyPublicOutput(
  fields,
  params = { stateTreeDepth: 2, deactivateTreeDepth: 4 },
) {
  return publicOutput(
    [
      'magic',
      'version',
      'circuit_id',
      'hash_scheme',
      'state_tree_depth',
      'deactivate_tree_depth',
      'deactivate_root_hash',
      'coord_pub_key_hash',
      'nullifier',
      'c1_hash',
      'c2_hash',
      'shared_key_hash',
      'deactivate_leaf_hash',
      'd1_hash',
      'd2_hash',
      'rerandomize_binding_hash',
      'new_pub_key_hash',
      'poll_id',
      'input_hash',
    ],
    [
      PUBLIC_OUTPUT_MAGIC,
      NATIVE_PUBLIC_OUTPUT_VERSION,
      ADD_NEW_KEY_NATIVE_CIRCUIT_ID,
      STARKNET_POSEIDON_HASH_SCHEME,
      BigInt(params.stateTreeDepth),
      BigInt(params.deactivateTreeDepth),
      fields.deactivateRootHash,
      fields.coordPubKeyHash,
      fields.nullifier,
      fields.c1Hash,
      fields.c2Hash,
      fields.sharedKeyHash,
      fields.deactivateLeafHash,
      fields.d1Hash,
      fields.d2Hash,
      fields.rerandomizeBindingHash,
      fields.newPubKeyHash,
      fields.pollId,
      fields.inputHash,
    ],
  );
}

export function canonicalNativeProcessDeactivatePublicOutput(
  fields,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  return publicOutput(
    [
      'magic',
      'version',
      'circuit_id',
      'hash_scheme',
      'state_tree_depth',
      'deactivate_tree_depth',
      'message_batch_size',
      'new_deactivate_root',
      'coord_pub_key_hash',
      'batch_start_hash',
      'batch_end_hash',
      'current_deactivate_commitment',
      'new_deactivate_commitment',
      'current_state_root',
      'expected_poll_id',
      'input_hash',
    ],
    [
      PUBLIC_OUTPUT_MAGIC,
      NATIVE_PUBLIC_OUTPUT_VERSION,
      PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID,
      STARKNET_POSEIDON_HASH_SCHEME,
      BigInt(params.stateTreeDepth),
      BigInt(params.deactivateTreeDepth),
      BigInt(params.messageBatchSize),
      fields.newDeactivateRoot,
      fields.coordPubKeyHash,
      fields.batchStartHash,
      fields.batchEndHash,
      fields.currentDeactivateCommitment,
      fields.newDeactivateCommitment,
      fields.currentStateRoot,
      fields.expectedPollId,
      fields.inputHash,
    ],
  );
}
