import {
  SMALL_PROCESS_MESSAGES_PARAMS,
  TREE_ARITY,
} from '../constants.mjs';
import {
  deepMapBigInt,
  parseBigInt,
  processMessagesInputHash,
} from '../compat/encoding.mjs';
import { hash13, hashLeftRight } from '../compat/poseidon.mjs';
import { canonicalProcessMessagesPublicOutput } from '../public-output.mjs';
import { evaluateProcessOneStateTransition } from './process-one.mjs';

const MSG_LENGTH = 10;
const ENC_PUB_KEY_LENGTH = 2;
const U32_MODULUS = 1n << 32n;

function assertSupportedParams(params) {
  if (
    params.stateTreeDepth !== 2 ||
    params.voteOptionTreeDepth !== 1 ||
    params.messageBatchSize !== 5
  ) {
    throw new Error('only AMACI ProcessMessages(2, 1, 5) is supported in this migration step');
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
  return hash13([
    ...message.map((value, idx) => parseBigInt(value, `message[${idx}]`)),
    parseBigInt(encPubKey[0], 'encPubKey[0]'),
    parseBigInt(encPubKey[1], 'encPubKey[1]'),
    parseBigInt(prevHash, 'prevHash'),
  ]);
}

export function processMessageHashChain(messages, encPubKeys, batchStartHash) {
  expectMatrixShape(messages, SMALL_PROCESS_MESSAGES_PARAMS.messageBatchSize, MSG_LENGTH, 'msgs');
  expectMatrixShape(
    encPubKeys,
    SMALL_PROCESS_MESSAGES_PARAMS.messageBatchSize,
    ENC_PUB_KEY_LENGTH,
    'encPubKeys',
  );

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
    inputHash: parseBigInt(rawInput.inputHash, 'inputHash'),
    coordPubKey: deepMapBigInt(rawInput.coordPubKey),
    batchStartHash: parseBigInt(rawInput.batchStartHash, 'batchStartHash'),
    batchEndHash: parseBigInt(rawInput.batchEndHash, 'batchEndHash'),
    currentStateRoot: parseBigInt(rawInput.currentStateRoot, 'currentStateRoot'),
    currentStateSalt: parseBigInt(rawInput.currentStateSalt, 'currentStateSalt'),
    currentStateCommitment: parseBigInt(rawInput.currentStateCommitment, 'currentStateCommitment'),
    newStateCommitment: parseBigInt(rawInput.newStateCommitment, 'newStateCommitment'),
    newStateRoot:
      rawInput.newStateRoot === undefined
        ? undefined
        : parseBigInt(rawInput.newStateRoot, 'newStateRoot'),
    newStateSalt: parseBigInt(rawInput.newStateSalt, 'newStateSalt'),
    activeStateRoot: parseBigInt(rawInput.activeStateRoot, 'activeStateRoot'),
    deactivateRoot: parseBigInt(rawInput.deactivateRoot, 'deactivateRoot'),
    deactivateCommitment: parseBigInt(rawInput.deactivateCommitment, 'deactivateCommitment'),
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

  const coordPubKeyHash = hashLeftRight(input.coordPubKey[0], input.coordPubKey[1]);
  const currentStateCommitment = hashLeftRight(input.currentStateRoot, input.currentStateSalt);
  expectEqual(currentStateCommitment, input.currentStateCommitment, 'currentStateCommitment');

  const deactivateCommitment = hashLeftRight(input.activeStateRoot, input.deactivateRoot);
  expectEqual(deactivateCommitment, input.deactivateCommitment, 'deactivateCommitment');

  if (input.newStateRoot !== undefined) {
    const newStateCommitment = hashLeftRight(input.newStateRoot, input.newStateSalt);
    expectEqual(newStateCommitment, input.newStateCommitment, 'newStateCommitment');
  }

  const expectedInputHash = processMessagesInputHash(
    input.packedVals,
    coordPubKeyHash,
    input.batchStartHash,
    input.batchEndHash,
    input.currentStateCommitment,
    input.newStateCommitment,
    input.deactivateCommitment,
    input.expectedPollId,
  );
  expectEqual(expectedInputHash, input.inputHash, 'inputHash');

  const { chain: messageHashChain, endHash } = processMessageHashChain(
    input.msgs,
    input.encPubKeys,
    input.batchStartHash,
  );
  expectEqual(endHash, input.batchEndHash, 'batchEndHash');

  const publicFields = {
    packedVals: input.packedVals,
    coordPubKeyHash,
    batchStartHash: input.batchStartHash,
    batchEndHash: input.batchEndHash,
    currentStateCommitment: input.currentStateCommitment,
    newStateCommitment: input.newStateCommitment,
    deactivateCommitment: input.deactivateCommitment,
    expectedPollId: input.expectedPollId,
    inputHash: input.inputHash,
  };

  return {
    params,
    publicFields,
    publicOutput: canonicalProcessMessagesPublicOutput(publicFields, params),
    derived: {
      ...unpacked,
      coordPubKeyHash,
      currentStateCommitment,
      deactivateCommitment,
      expectedPollId: input.expectedPollId,
      messageHashChain,
      inputHash: expectedInputHash,
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
