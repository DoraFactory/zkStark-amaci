import {
  PROCESS_MESSAGES_NATIVE_INPUT_HASH_DOMAIN,
  SMALL_PROCESS_MESSAGES_PARAMS,
  TREE_ARITY,
} from '../constants.mjs';
import {
  deepMapBigInt,
  parseBigInt,
} from '../encoding.mjs';
import { nativeHashFelts, nativeHashPoint } from '../native-hash.mjs';
import { evaluateProcessOneStateTransition } from './process-one.mjs';

const MSG_LENGTH = 10;
const ENC_PUB_KEY_LENGTH = 2;
const U32_MODULUS = 1n << 32n;

function assertSupportedParams(params) {
  if (
    params.stateTreeDepth !== 2 ||
    params.voteOptionTreeDepth !== 1 ||
    params.messageBatchSize !== 3
  ) {
    throw new Error('only AMACI ProcessMessages(2, 1, 3) is supported');
  }
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch: expected ${expected.toString()}, got ${actual.toString()}`);
  }
}

function expectEmptyMessageTransition(messageIndex, encPubKey, transition) {
  if (parseBigInt(encPubKey[0], `encPubKeys[${messageIndex}][0]`) === 0n && transition.input.isValid !== 0n) {
    throw new Error(`empty message ${messageIndex} cannot drive a valid ProcessOne transition`);
  }
}

function expectProcessOneMessage(messageIndex, message, transition) {
  for (let i = 0; i < MSG_LENGTH; i += 1) {
    expectEqual(
      transition.input.msg[i],
      parseBigInt(message[i], `msgs[${messageIndex}][${i}]`),
      `processOneWitnesses[${messageIndex}].msg[${i}]`,
    );
  }
}

function expectVectorShape(vector, length, label) {
  if (!Array.isArray(vector) || vector.length !== length) {
    throw new Error(`${label} must contain ${length} values`);
  }
}

function expectMatrixShape(matrix, rows, cols, label) {
  if (!Array.isArray(matrix) || matrix.length !== rows) {
    throw new Error(`${label} must contain ${rows} rows`);
  }
  for (let i = 0; i < rows; i += 1) {
    expectVectorShape(matrix[i], cols, `${label}[${i}]`);
  }
}

function assertU32(value, label) {
  const n = parseBigInt(value, label);
  if (n < 0n || n >= U32_MODULUS) {
    throw new Error(`${label} must fit in 32 bits`);
  }
  return n;
}

export function packProcessMessagesVals({ isQuadraticCost, numSignUps, maxVoteOptions }) {
  const isQuadratic = assertU32(isQuadraticCost, 'isQuadraticCost');
  if (isQuadratic !== 0n && isQuadratic !== 1n) {
    throw new Error('isQuadraticCost must be 0 or 1');
  }
  return (
    (isQuadratic << 64n) +
    (assertU32(numSignUps, 'numSignUps') << 32n) +
    assertU32(maxVoteOptions, 'maxVoteOptions')
  );
}

export function unpackProcessMessagesPackedVals(packedVals) {
  const packed = parseBigInt(packedVals, 'packedVals');
  const mask32 = U32_MODULUS - 1n;
  return {
    isQuadraticCost: (packed >> 64n) & mask32,
    numSignUps: (packed >> 32n) & mask32,
    maxVoteOptions: packed & mask32,
  };
}

export function processMessageHash(message, encPubKey, prevHash) {
  expectVectorShape(message, MSG_LENGTH, 'message');
  expectVectorShape(encPubKey, ENC_PUB_KEY_LENGTH, 'encPubKey');
  return nativeHashFelts([
    ...message.map((value, idx) => parseBigInt(value, `message[${idx}]`)),
    parseBigInt(encPubKey[0], 'encPubKey[0]'),
    parseBigInt(encPubKey[1], 'encPubKey[1]'),
    parseBigInt(prevHash, 'prevHash'),
  ], 'messageHash');
}

export function processMessageHashChain(messages, encPubKeys, batchStartHash) {
  expectMatrixShape(messages, messages.length, MSG_LENGTH, 'msgs');
  expectMatrixShape(encPubKeys, messages.length, ENC_PUB_KEY_LENGTH, 'encPubKeys');

  const chain = [parseBigInt(batchStartHash, 'batchStartHash')];
  for (let i = 0; i < messages.length; i += 1) {
    const prevHash = chain[i];
    const isEmptyMessage = parseBigInt(encPubKeys[i][0], `encPubKeys[${i}][0]`) === 0n;
    chain.push(isEmptyMessage ? prevHash : processMessageHash(messages[i], encPubKeys[i], prevHash));
  }
  return {
    chain,
    endHash: chain.at(-1),
  };
}

export function evaluateProcessMessages(rawInput, params = SMALL_PROCESS_MESSAGES_PARAMS) {
  assertSupportedParams(params);
  expectVectorShape(rawInput.coordPubKey, 2, 'coordPubKey');
  expectMatrixShape(rawInput.msgs, params.messageBatchSize, MSG_LENGTH, 'msgs');
  expectMatrixShape(rawInput.encPubKeys, params.messageBatchSize, ENC_PUB_KEY_LENGTH, 'encPubKeys');

  const input = {
    packedVals: parseBigInt(rawInput.packedVals, 'packedVals'),
    coordPubKey: deepMapBigInt(rawInput.coordPubKey),
    batchStartHash: parseBigInt(rawInput.batchStartHash, 'batchStartHash'),
    batchEndHash:
      rawInput.batchEndHash === undefined
        ? undefined
        : parseBigInt(rawInput.batchEndHash, 'batchEndHash'),
    currentStateRoot: parseBigInt(rawInput.currentStateRoot, 'currentStateRoot'),
    currentStateSalt: parseBigInt(rawInput.currentStateSalt, 'currentStateSalt'),
    newStateRoot:
      rawInput.newStateRoot === undefined
        ? undefined
        : parseBigInt(rawInput.newStateRoot, 'newStateRoot'),
    newStateSalt: parseBigInt(rawInput.newStateSalt, 'newStateSalt'),
    activeStateRoot: parseBigInt(rawInput.activeStateRoot, 'activeStateRoot'),
    deactivateRoot: parseBigInt(rawInput.deactivateRoot, 'deactivateRoot'),
    expectedPollId: parseBigInt(rawInput.expectedPollId, 'expectedPollId'),
    msgs: deepMapBigInt(rawInput.msgs),
    encPubKeys: deepMapBigInt(rawInput.encPubKeys),
  };

  const unpacked = unpackProcessMessagesPackedVals(input.packedVals);
  if (unpacked.isQuadraticCost !== 0n && unpacked.isQuadraticCost !== 1n) {
    throw new Error('isQuadraticCost must be 0 or 1');
  }
  if (unpacked.maxVoteOptions > BigInt(TREE_ARITY ** params.voteOptionTreeDepth)) {
    throw new Error('maxVoteOptions exceeds vote option tree capacity');
  }
  if (unpacked.numSignUps > BigInt(TREE_ARITY ** params.stateTreeDepth)) {
    throw new Error('numSignUps exceeds state tree capacity');
  }

  expectEqual(
    packProcessMessagesVals(unpacked),
    input.packedVals,
    'packedVals',
  );

  const coordPubKeyHash = nativeHashPoint(input.coordPubKey, 'coordPubKey');
  const currentStateCommitment = nativeHashFelts(
    [input.currentStateRoot, input.currentStateSalt],
    'currentStateCommitment',
  );
  const deactivateCommitment = nativeHashFelts(
    [input.activeStateRoot, input.deactivateRoot],
    'deactivateCommitment',
  );
  const newStateCommitment = input.newStateRoot === undefined
    ? 0n
    : nativeHashFelts([input.newStateRoot, input.newStateSalt], 'newStateCommitment');
  const { chain: messageHashChain, endHash } = processMessageHashChain(
    input.msgs,
    input.encPubKeys,
    input.batchStartHash,
  );
  if (input.batchEndHash !== undefined) {
    expectEqual(endHash, input.batchEndHash, 'batchEndHash');
  }

  const inputHash = nativeHashFelts([
    PROCESS_MESSAGES_NATIVE_INPUT_HASH_DOMAIN,
    input.packedVals,
    coordPubKeyHash,
    input.batchStartHash,
    endHash,
    currentStateCommitment,
    newStateCommitment,
    deactivateCommitment,
    input.expectedPollId,
  ], 'processMessagesInputHash');

  const publicFields = {
    packedVals: input.packedVals,
    coordPubKeyHash,
    batchStartHash: input.batchStartHash,
    batchEndHash: endHash,
    currentStateCommitment,
    newStateCommitment,
    deactivateCommitment,
    expectedPollId: input.expectedPollId,
    inputHash,
  };

  return {
    params,
    publicFields,
    derived: {
      ...unpacked,
      coordPubKeyHash,
      currentStateCommitment,
      newStateCommitment,
      deactivateCommitment,
      expectedPollId: input.expectedPollId,
      messageHashChain,
      inputHash,
    },
  };
}

export function evaluateProcessMessagesStateTransitions(rawInput, params = SMALL_PROCESS_MESSAGES_PARAMS) {
  assertSupportedParams(params);
  if (!Array.isArray(rawInput.processOneWitnesses) || rawInput.processOneWitnesses.length !== params.messageBatchSize) {
    throw new Error(`processOneWitnesses must contain ${params.messageBatchSize} witnesses`);
  }

  const input = {
    coordPrivKey: parseBigInt(rawInput.coordPrivKey, 'coordPrivKey'),
    currentStateRoot: parseBigInt(rawInput.currentStateRoot, 'currentStateRoot'),
    activeStateRoot: parseBigInt(rawInput.activeStateRoot, 'activeStateRoot'),
    newStateRoot:
      rawInput.newStateRoot === undefined
        ? undefined
        : parseBigInt(rawInput.newStateRoot, 'newStateRoot'),
  };

  let currentRoot = input.currentStateRoot;
  const transitions = Array.from({ length: params.messageBatchSize });
  for (let i = params.messageBatchSize - 1; i >= 0; i -= 1) {
    const evaluated = evaluateProcessOneStateTransition(rawInput.processOneWitnesses[i], params);
    expectEqual(evaluated.input.coordPrivKey, input.coordPrivKey, `processOneWitnesses[${i}].coordPrivKey`);
    expectEqual(evaluated.input.currentStateRoot, currentRoot, `processOneWitnesses[${i}].currentStateRoot`);
    expectEqual(evaluated.input.activeStateRoot, input.activeStateRoot, `processOneWitnesses[${i}].activeStateRoot`);
    transitions[i] = evaluated;
    currentRoot = evaluated.derived.newStateRoot;
  }

  if (input.newStateRoot !== undefined) {
    expectEqual(currentRoot, input.newStateRoot, 'newStateRoot');
  }

  return {
    params,
    input,
    transitions,
    derived: {
      currentStateRoot: input.currentStateRoot,
      coordPrivKey: input.coordPrivKey,
      activeStateRoot: input.activeStateRoot,
      newStateRoot: currentRoot,
    },
  };
}

export function evaluateProcessMessagesStateful(rawInput, params = SMALL_PROCESS_MESSAGES_PARAMS) {
  const boundary = evaluateProcessMessages(rawInput, params);
  const state = evaluateProcessMessagesStateTransitions(rawInput, params);

  expectEqual(state.derived.currentStateRoot, parseBigInt(rawInput.currentStateRoot, 'currentStateRoot'), 'currentStateRoot');
  expectEqual(state.derived.activeStateRoot, parseBigInt(rawInput.activeStateRoot, 'activeStateRoot'), 'activeStateRoot');
  if (rawInput.newStateRoot === undefined) {
    throw new Error('newStateRoot is required for stateful ProcessMessages evaluation');
  }
  expectEqual(state.derived.newStateRoot, parseBigInt(rawInput.newStateRoot, 'newStateRoot'), 'newStateRoot');
  for (let i = 0; i < params.messageBatchSize; i += 1) {
    expectEqual(state.transitions[i].input.isQuadraticCost, boundary.derived.isQuadraticCost, `processOneWitnesses[${i}].isQuadraticCost`);
    expectEqual(state.transitions[i].input.numSignUps, boundary.derived.numSignUps, `processOneWitnesses[${i}].numSignUps`);
    expectEqual(state.transitions[i].input.maxVoteOptions, boundary.derived.maxVoteOptions, `processOneWitnesses[${i}].maxVoteOptions`);
    expectEqual(state.transitions[i].input.expectedPollId, boundary.derived.expectedPollId, `processOneWitnesses[${i}].expectedPollId`);
    expectProcessOneMessage(i, rawInput.msgs[i], state.transitions[i]);
    expectEmptyMessageTransition(i, rawInput.encPubKeys[i], state.transitions[i]);
  }

  return {
    params,
    boundary,
    state,
    publicFields: boundary.publicFields,
    publicOutput: boundary.publicOutput,
    derived: {
      ...boundary.derived,
      stateTransitionNewStateRoot: state.derived.newStateRoot,
    },
  };
}
