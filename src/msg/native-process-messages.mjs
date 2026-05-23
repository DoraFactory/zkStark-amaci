import {
  NATIVE_PUBLIC_OUTPUT_VERSION,
  PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
  PROCESS_MESSAGES_NATIVE_INPUT_HASH_DOMAIN,
  PUBLIC_OUTPUT_MAGIC,
  SMALL_PROCESS_MESSAGES_PARAMS,
  STARKNET_POSEIDON_HASH_SCHEME,
  TREE_ARITY,
} from '../constants.mjs';
import { decimalize } from '../compat/encoding.mjs';
import { poseidonManyFelts } from '../integrity/hashes.mjs';
import { toStarkFelt } from '../tally/native-tally-votes.mjs';
import { evaluateProcessMessagesStateful } from './process-messages.mjs';
import {
  nativeProcessMessageTransitionContexts,
  nativeProcessMessagesStateRoots,
} from './native-process-roots.mjs';
import { packProcessMessagesVals, unpackProcessMessagesPackedVals } from './process-messages.mjs';

const MSG_LENGTH = 10;
const ENC_PUB_KEY_LENGTH = 2;
const U32_MAX = (1n << 32n) - 1n;

function assertSupportedParams(params) {
  if (
    params.stateTreeDepth !== 2 ||
    params.voteOptionTreeDepth !== 1 ||
    params.messageBatchSize !== 3
  ) {
    throw new Error('only AMACI-STARK v2 ProcessMessagesNativeBoundary(2, 1, 3) is supported');
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

function assertU32(value, label) {
  if (value < 0n || value > U32_MAX) {
    throw new Error(`${label} must fit in u32`);
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
  return encPubKey[0] === 0n ? previousHash : messageHash(message, encPubKey, previousHash);
}

function canonicalNativeProcessMessagesPublicOutput(fields, params) {
  const labels = [
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
  ];
  const felts = [
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
  ];
  return {
    labels,
    felts,
    decimalFelts: felts.map(decimalize),
  };
}

export function evaluateNativeProcessMessagesBoundary(rawInput, params = SMALL_PROCESS_MESSAGES_PARAMS) {
  assertSupportedParams(params);
  const batchSize = params.messageBatchSize;
  const maxVoteOptionsCapacity = BigInt(TREE_ARITY ** params.voteOptionTreeDepth);
  const maxSignupsCapacity = BigInt(TREE_ARITY ** params.stateTreeDepth);

  const coordPubKey = feltVector(rawInput.coordPubKey, 2, 'coordPubKey');
  expectMatrixShape(rawInput.msgs, batchSize, MSG_LENGTH, 'msgs');
  expectMatrixShape(rawInput.encPubKeys, batchSize, ENC_PUB_KEY_LENGTH, 'encPubKeys');

  const unpacked = unpackProcessMessagesPackedVals(rawInput.packedVals);
  assertU32(unpacked.isQuadraticCost, 'isQuadraticCost');
  assertU32(unpacked.numSignUps, 'numSignUps');
  assertU32(unpacked.maxVoteOptions, 'maxVoteOptions');
  if (unpacked.isQuadraticCost !== 0n && unpacked.isQuadraticCost !== 1n) {
    throw new Error('isQuadraticCost must be 0 or 1');
  }
  if (unpacked.maxVoteOptions > maxVoteOptionsCapacity) {
    throw new Error('maxVoteOptions exceeds vote option tree capacity');
  }
  if (unpacked.numSignUps > maxSignupsCapacity) {
    throw new Error('numSignUps exceeds state tree capacity');
  }

  const packedVals = toStarkFelt(packProcessMessagesVals(unpacked), 'packedVals');
  const batchStartHash = toStarkFelt(rawInput.batchStartHash, 'batchStartHash');
  const nativeState = Array.isArray(rawInput.processOneWitnesses)
    ? nativeProcessMessagesStateRoots(evaluateProcessMessagesStateful(rawInput).state, rawInput)
    : undefined;
  const currentStateRoot = nativeState?.currentStateRoot ?? toStarkFelt(rawInput.currentStateRoot, 'currentStateRoot');
  const currentStateSalt = toStarkFelt(rawInput.currentStateSalt, 'currentStateSalt');
  const newStateRoot = nativeState?.newStateRoot ?? toStarkFelt(rawInput.newStateRoot, 'newStateRoot');
  const newStateSalt = toStarkFelt(rawInput.newStateSalt, 'newStateSalt');
  const activeStateRoot = nativeState?.activeStateRoot ?? toStarkFelt(rawInput.activeStateRoot, 'activeStateRoot');
  const deactivateRoot = toStarkFelt(rawInput.deactivateRoot, 'deactivateRoot');
  const expectedPollId = toStarkFelt(rawInput.expectedPollId, 'expectedPollId');
  const msgs = rawInput.msgs.map((row, index) => feltVector(row, MSG_LENGTH, `msgs[${index}]`));
  const encPubKeys = rawInput.encPubKeys.map((row, index) =>
    feltVector(row, ENC_PUB_KEY_LENGTH, `encPubKeys[${index}]`),
  );

  const coordPubKeyHash = hash2(coordPubKey[0], coordPubKey[1]);
  const currentStateCommitment = hash2(currentStateRoot, currentStateSalt);
  const newStateCommitment = hash2(newStateRoot, newStateSalt);
  const deactivateCommitment = hash2(activeStateRoot, deactivateRoot);

  const messageHashChain = [batchStartHash];
  for (let index = 0; index < batchSize; index += 1) {
    messageHashChain.push(messageHashOrEmpty(msgs[index], encPubKeys[index], messageHashChain[index]));
  }
  const batchEndHash = messageHashChain.at(-1);
  const inputHash = hashMany([
    PROCESS_MESSAGES_NATIVE_INPUT_HASH_DOMAIN,
    packedVals,
    coordPubKeyHash,
    batchStartHash,
    batchEndHash,
    currentStateCommitment,
    newStateCommitment,
    deactivateCommitment,
    expectedPollId,
  ]);

  const publicFields = {
    packedVals,
    coordPubKeyHash,
    batchStartHash,
    batchEndHash,
    currentStateCommitment,
    newStateCommitment,
    deactivateCommitment,
    expectedPollId,
    inputHash,
  };

  return {
    params,
    publicFields,
    publicOutput: canonicalNativeProcessMessagesPublicOutput(publicFields, params),
    nativeWitness: {
      isQuadraticCost: unpacked.isQuadraticCost,
      numSignUps: unpacked.numSignUps,
      maxVoteOptions: unpacked.maxVoteOptions,
      coordPubKey,
      currentStateRoot,
      currentStateSalt,
      newStateRoot,
      newStateSalt,
      activeStateRoot,
      deactivateRoot,
      expectedPollId,
      msgs,
      encPubKeys,
    },
    derived: {
      ...unpacked,
      coordPubKeyHash,
      currentStateCommitment,
      newStateCommitment,
      deactivateCommitment,
      messageHashChain,
      batchEndHash,
      inputHash,
    },
  };
}

function zeroVector(length) {
  return Array.from({ length }, () => 0n);
}

function validateSegment(segment) {
  const startIndex = Number(segment?.startIndex);
  const endIndex = Number(segment?.endIndex);
  if (
    !Number.isInteger(startIndex) ||
    !Number.isInteger(endIndex) ||
    startIndex < 0 ||
    startIndex >= endIndex ||
    endIndex > SMALL_PROCESS_MESSAGES_PARAMS.messageBatchSize
  ) {
    throw new Error('ProcessMessages segment must satisfy 0 <= startIndex < endIndex <= 3');
  }
  const length = endIndex - startIndex;
  if (length !== 2 && length !== 3) {
    throw new Error('ProcessMessages stage segment supports only 2-message or 3-message segments');
  }
  return { startIndex, endIndex, length };
}

export function evaluateNativeProcessMessagesBoundarySegment(
  rawInput,
  segment,
  params = SMALL_PROCESS_MESSAGES_PARAMS,
) {
  assertSupportedParams(params);
  const { startIndex, endIndex, length } = validateSegment(segment);
  const full = evaluateNativeProcessMessagesBoundary(rawInput, params);
  const stateful = evaluateProcessMessagesStateful(rawInput);
  const transitionContexts = nativeProcessMessageTransitionContexts(stateful.state, rawInput);

  const msgs = [];
  const encPubKeys = [];
  for (let index = startIndex; index < endIndex; index += 1) {
    msgs.push(feltVector(rawInput.msgs[index], MSG_LENGTH, `msgs[${index}]`));
    encPubKeys.push(feltVector(rawInput.encPubKeys[index], ENC_PUB_KEY_LENGTH, `encPubKeys[${index}]`));
  }
  while (msgs.length < params.messageBatchSize) {
    msgs.push(zeroVector(MSG_LENGTH));
    encPubKeys.push(zeroVector(ENC_PUB_KEY_LENGTH));
  }

  const currentContext = transitionContexts[endIndex - 1];
  const newContext = transitionContexts[startIndex];
  const currentStateRoot = currentContext.currentStateRoot;
  const currentStateSalt = endIndex === params.messageBatchSize
    ? toStarkFelt(rawInput.currentStateSalt, 'currentStateSalt')
    : toStarkFelt(rawInput.newStateSalt, 'segmentCurrentStateSalt');
  const newStateRoot = newContext.newStateRoot;
  const newStateSalt = toStarkFelt(rawInput.newStateSalt, 'newStateSalt');
  const activeStateRoot = newContext.activeStateRoot;
  const deactivateRoot = toStarkFelt(rawInput.deactivateRoot, 'deactivateRoot');
  const batchStartHash = full.derived.messageHashChain[startIndex];
  const batchEndHash = full.derived.messageHashChain[endIndex];

  const currentStateCommitment = hash2(currentStateRoot, currentStateSalt);
  const newStateCommitment = hash2(newStateRoot, newStateSalt);
  const deactivateCommitment = hash2(activeStateRoot, deactivateRoot);
  const inputHash = hashMany([
    PROCESS_MESSAGES_NATIVE_INPUT_HASH_DOMAIN,
    full.publicFields.packedVals,
    full.publicFields.coordPubKeyHash,
    batchStartHash,
    batchEndHash,
    currentStateCommitment,
    newStateCommitment,
    deactivateCommitment,
    full.publicFields.expectedPollId,
  ]);

  const publicFields = {
    packedVals: full.publicFields.packedVals,
    coordPubKeyHash: full.publicFields.coordPubKeyHash,
    batchStartHash,
    batchEndHash,
    currentStateCommitment,
    newStateCommitment,
    deactivateCommitment,
    expectedPollId: full.publicFields.expectedPollId,
    inputHash,
  };

  return {
    params,
    segment: { startIndex, endIndex, length },
    publicFields,
    publicOutput: canonicalNativeProcessMessagesPublicOutput(publicFields, params),
    nativeWitness: {
      isQuadraticCost: full.nativeWitness.isQuadraticCost,
      numSignUps: full.nativeWitness.numSignUps,
      maxVoteOptions: full.nativeWitness.maxVoteOptions,
      coordPubKey: full.nativeWitness.coordPubKey,
      currentStateRoot,
      currentStateSalt,
      newStateRoot,
      newStateSalt,
      activeStateRoot,
      deactivateRoot,
      expectedPollId: full.nativeWitness.expectedPollId,
      msgs,
      encPubKeys,
    },
    derived: {
      ...full.derived,
      segmentStartIndex: BigInt(startIndex),
      segmentEndIndex: BigInt(endIndex),
      segmentLength: BigInt(length),
      segmentBatchStartHash: batchStartHash,
      segmentBatchEndHash: batchEndHash,
      currentStateCommitment,
      newStateCommitment,
      deactivateCommitment,
      inputHash,
    },
  };
}
