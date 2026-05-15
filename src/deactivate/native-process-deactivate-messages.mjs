import {
  NATIVE_PUBLIC_OUTPUT_VERSION,
  PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID,
  PROCESS_DEACTIVATE_NATIVE_INPUT_HASH_DOMAIN,
  PUBLIC_OUTPUT_MAGIC,
  SMALL_PROCESS_DEACTIVATE_PARAMS,
  STARKNET_POSEIDON_HASH_SCHEME,
} from '../constants.mjs';
import { decimalize } from '../compat/encoding.mjs';
import { poseidonManyFelts } from '../integrity/hashes.mjs';
import { toStarkFelt } from '../tally/native-tally-votes.mjs';

const MSG_LENGTH = 10;
const ENC_PUB_KEY_LENGTH = 2;

function assertSupportedParams(params) {
  if (
    params.stateTreeDepth !== 2 ||
    params.deactivateTreeDepth !== 4 ||
    params.messageBatchSize !== 5
  ) {
    throw new Error('only AMACI-STARK v2 ProcessDeactivateNativeBoundary(2, 4, 5) is supported');
  }
}

function feltVector(values, expected, label) {
  if (!Array.isArray(values) || values.length !== expected) {
    throw new Error(`${label} must contain ${expected} values`);
  }
  return values.map((value, index) => toStarkFelt(value, `${label}[${index}]`));
}

function expectMatrixShape(matrix, rows, cols, label) {
  if (!Array.isArray(matrix) || matrix.length !== rows) {
    throw new Error(`${label} must contain ${rows} rows`);
  }
  for (let i = 0; i < rows; i += 1) {
    feltVector(matrix[i], cols, `${label}[${i}]`);
  }
}

function hashMany(values) {
  return poseidonManyFelts(values.map((value, index) => toStarkFelt(value, `hash[${index}]`)));
}

function hash2(left, right) {
  return hashMany([left, right]);
}

function messageHash(message, encPubKey, previousHash) {
  return hashMany([...message, encPubKey[0], encPubKey[1], previousHash]);
}

function messageHashOrEmpty(message, encPubKey, previousHash) {
  return message[0] === 0n ? previousHash : messageHash(message, encPubKey, previousHash);
}

function canonicalNativeProcessDeactivatePublicOutput(fields, params) {
  const labels = [
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
  ];
  const felts = [
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
  ];
  return {
    labels,
    felts,
    decimalFelts: felts.map(decimalize),
  };
}

export function evaluateNativeProcessDeactivateMessagesBoundary(
  rawInput,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  assertSupportedParams(params);
  const batchSize = params.messageBatchSize;

  const coordPubKey = feltVector(rawInput.coordPubKey, 2, 'coordPubKey');
  expectMatrixShape(rawInput.msgs, batchSize, MSG_LENGTH, 'msgs');
  expectMatrixShape(rawInput.encPubKeys, batchSize, ENC_PUB_KEY_LENGTH, 'encPubKeys');

  const newDeactivateRoot = toStarkFelt(rawInput.newDeactivateRoot, 'newDeactivateRoot');
  const batchStartHash = toStarkFelt(rawInput.batchStartHash, 'batchStartHash');
  const currentActiveStateRoot = toStarkFelt(rawInput.currentActiveStateRoot, 'currentActiveStateRoot');
  const currentDeactivateRoot = toStarkFelt(rawInput.currentDeactivateRoot, 'currentDeactivateRoot');
  const newActiveStateRoot = toStarkFelt(rawInput.newActiveStateRoot, 'newActiveStateRoot');
  const currentStateRoot = toStarkFelt(rawInput.currentStateRoot, 'currentStateRoot');
  const expectedPollId = toStarkFelt(rawInput.expectedPollId, 'expectedPollId');
  const msgs = rawInput.msgs.map((row, index) => feltVector(row, MSG_LENGTH, `msgs[${index}]`));
  const encPubKeys = rawInput.encPubKeys.map((row, index) =>
    feltVector(row, ENC_PUB_KEY_LENGTH, `encPubKeys[${index}]`),
  );

  const coordPubKeyHash = hash2(coordPubKey[0], coordPubKey[1]);
  const currentDeactivateCommitment = hash2(currentActiveStateRoot, currentDeactivateRoot);
  const newDeactivateCommitment = hash2(newActiveStateRoot, newDeactivateRoot);

  const messageHashChain = [batchStartHash];
  for (let index = 0; index < batchSize; index += 1) {
    messageHashChain.push(messageHashOrEmpty(msgs[index], encPubKeys[index], messageHashChain[index]));
  }
  const batchEndHash = messageHashChain.at(-1);
  const inputHash = hashMany([
    PROCESS_DEACTIVATE_NATIVE_INPUT_HASH_DOMAIN,
    newDeactivateRoot,
    coordPubKeyHash,
    batchStartHash,
    batchEndHash,
    currentDeactivateCommitment,
    newDeactivateCommitment,
    currentStateRoot,
    expectedPollId,
  ]);

  const publicFields = {
    newDeactivateRoot,
    coordPubKeyHash,
    batchStartHash,
    batchEndHash,
    currentDeactivateCommitment,
    newDeactivateCommitment,
    currentStateRoot,
    expectedPollId,
    inputHash,
  };

  return {
    params,
    publicFields,
    publicOutput: canonicalNativeProcessDeactivatePublicOutput(publicFields, params),
    nativeWitness: {
      coordPubKey,
      currentActiveStateRoot,
      currentDeactivateRoot,
      newActiveStateRoot,
      msgs,
      encPubKeys,
    },
    derived: {
      coordPubKeyHash,
      currentDeactivateCommitment,
      newDeactivateCommitment,
      messageHashChain,
      batchEndHash,
      inputHash,
    },
  };
}
