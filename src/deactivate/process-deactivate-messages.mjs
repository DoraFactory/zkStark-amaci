import { SMALL_PROCESS_DEACTIVATE_PARAMS } from '../constants.mjs';
import { deepMapBigInt, parseBigInt, processDeactivateInputHash } from '../compat/encoding.mjs';
import { hash13, hashLeftRight } from '../compat/poseidon.mjs';
import { babyjubScalarMul } from '../compat/babyjub.mjs';
import { canonicalProcessDeactivatePublicOutput } from '../public-output.mjs';
import { evaluateProcessDeactivateOne } from './process-deactivate-one.mjs';
import { poseidonDecryptWithoutCheck7, unpackCommandData } from '../msg/process-one.mjs';

const MSG_LENGTH = 10;
const ENC_PUB_KEY_LENGTH = 2;

function assertSupportedParams(params) {
  if (
    params.stateTreeDepth !== 2 ||
    params.deactivateTreeDepth !== 4 ||
    params.messageBatchSize !== 5
  ) {
    throw new Error('only AMACI ProcessDeactivateMessages(2, 5) is supported in this migration step');
  }
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch: expected ${expected.toString()}, got ${actual.toString()}`);
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

function expectProcessOneMessageCommand(messageIndex, rawInput, transition) {
  const msg = rawInput.msgs[messageIndex];
  if (parseBigInt(msg[0], `msgs[${messageIndex}][0]`) === 0n) {
    return undefined;
  }
  const coordPrivKey = parseBigInt(rawInput.coordPrivKey, 'coordPrivKey');
  const encPubKey = deepMapBigInt(rawInput.encPubKeys[messageIndex]);
  const sharedKey = babyjubScalarMul(encPubKey, coordPrivKey);
  const decryptedCommand = poseidonDecryptWithoutCheck7(msg, sharedKey);
  const unpacked = unpackCommandData(decryptedCommand[0]);
  const input = transition.input;

  expectEqual(decryptedCommand[0], input.packedCmd[0], `processOneWitnesses[${messageIndex}].packedCmd[0]`);
  expectEqual(decryptedCommand[1], input.packedCmd[1], `processOneWitnesses[${messageIndex}].packedCmd[1]`);
  expectEqual(decryptedCommand[2], input.packedCmd[2], `processOneWitnesses[${messageIndex}].packedCmd[2]`);
  expectEqual(decryptedCommand[4], input.cmdSigR8[0], `processOneWitnesses[${messageIndex}].cmdSigR8[0]`);
  expectEqual(decryptedCommand[5], input.cmdSigR8[1], `processOneWitnesses[${messageIndex}].cmdSigR8[1]`);
  expectEqual(decryptedCommand[6], input.cmdSigS, `processOneWitnesses[${messageIndex}].cmdSigS`);
  expectEqual(unpacked.pollId, input.cmdPollId, `processOneWitnesses[${messageIndex}].cmdPollId`);
  expectEqual(unpacked.stateIndex, input.cmdStateIndex, `processOneWitnesses[${messageIndex}].cmdStateIndex`);
  return {
    sharedKey,
    decryptedCommand,
  };
}

export function processDeactivateMessageHash(message, encPubKey, prevHash) {
  expectVectorShape(message, MSG_LENGTH, 'message');
  expectVectorShape(encPubKey, ENC_PUB_KEY_LENGTH, 'encPubKey');
  return hash13([
    ...message.map((value, idx) => parseBigInt(value, `message[${idx}]`)),
    parseBigInt(encPubKey[0], 'encPubKey[0]'),
    parseBigInt(encPubKey[1], 'encPubKey[1]'),
    parseBigInt(prevHash, 'prevHash'),
  ]);
}

export function processDeactivateMessageHashChain(messages, encPubKeys, batchStartHash) {
  expectMatrixShape(
    messages,
    SMALL_PROCESS_DEACTIVATE_PARAMS.messageBatchSize,
    MSG_LENGTH,
    'msgs',
  );
  expectMatrixShape(
    encPubKeys,
    SMALL_PROCESS_DEACTIVATE_PARAMS.messageBatchSize,
    ENC_PUB_KEY_LENGTH,
    'encPubKeys',
  );

  const chain = [parseBigInt(batchStartHash, 'batchStartHash')];
  for (let i = 0; i < messages.length; i += 1) {
    const prevHash = chain[i];
    const isEmptyMessage = parseBigInt(messages[i][0], `msgs[${i}][0]`) === 0n;
    chain.push(
      isEmptyMessage ? prevHash : processDeactivateMessageHash(messages[i], encPubKeys[i], prevHash),
    );
  }
  return {
    chain,
    endHash: chain.at(-1),
  };
}

export function evaluateProcessDeactivateMessages(
  rawInput,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  assertSupportedParams(params);
  expectVectorShape(rawInput.coordPubKey, 2, 'coordPubKey');
  expectMatrixShape(rawInput.msgs, params.messageBatchSize, MSG_LENGTH, 'msgs');
  expectMatrixShape(rawInput.encPubKeys, params.messageBatchSize, ENC_PUB_KEY_LENGTH, 'encPubKeys');

  const input = {
    inputHash: parseBigInt(rawInput.inputHash, 'inputHash'),
    newDeactivateRoot: parseBigInt(rawInput.newDeactivateRoot, 'newDeactivateRoot'),
    coordPubKey: deepMapBigInt(rawInput.coordPubKey),
    batchStartHash: parseBigInt(rawInput.batchStartHash, 'batchStartHash'),
    batchEndHash: parseBigInt(rawInput.batchEndHash, 'batchEndHash'),
    currentActiveStateRoot: parseBigInt(rawInput.currentActiveStateRoot, 'currentActiveStateRoot'),
    currentDeactivateRoot: parseBigInt(rawInput.currentDeactivateRoot, 'currentDeactivateRoot'),
    currentDeactivateCommitment: parseBigInt(
      rawInput.currentDeactivateCommitment,
      'currentDeactivateCommitment',
    ),
    newDeactivateCommitment: parseBigInt(rawInput.newDeactivateCommitment, 'newDeactivateCommitment'),
    currentStateRoot: parseBigInt(rawInput.currentStateRoot, 'currentStateRoot'),
    expectedPollId: parseBigInt(rawInput.expectedPollId, 'expectedPollId'),
    msgs: deepMapBigInt(rawInput.msgs),
    encPubKeys: deepMapBigInt(rawInput.encPubKeys),
  };

  const coordPubKeyHash = hashLeftRight(input.coordPubKey[0], input.coordPubKey[1]);
  const currentDeactivateCommitment = hashLeftRight(
    input.currentActiveStateRoot,
    input.currentDeactivateRoot,
  );
  expectEqual(
    currentDeactivateCommitment,
    input.currentDeactivateCommitment,
    'currentDeactivateCommitment',
  );

  const expectedInputHash = processDeactivateInputHash(
    input.newDeactivateRoot,
    coordPubKeyHash,
    input.batchStartHash,
    input.batchEndHash,
    input.currentDeactivateCommitment,
    input.newDeactivateCommitment,
    input.currentStateRoot,
    input.expectedPollId,
  );
  expectEqual(expectedInputHash, input.inputHash, 'inputHash');

  const { chain: messageHashChain, endHash } = processDeactivateMessageHashChain(
    input.msgs,
    input.encPubKeys,
    input.batchStartHash,
  );
  expectEqual(endHash, input.batchEndHash, 'batchEndHash');

  const publicFields = {
    newDeactivateRoot: input.newDeactivateRoot,
    coordPubKeyHash,
    batchStartHash: input.batchStartHash,
    batchEndHash: input.batchEndHash,
    currentDeactivateCommitment: input.currentDeactivateCommitment,
    newDeactivateCommitment: input.newDeactivateCommitment,
    currentStateRoot: input.currentStateRoot,
    expectedPollId: input.expectedPollId,
    inputHash: input.inputHash,
  };

  return {
    params,
    input,
    publicFields,
    publicOutput: canonicalProcessDeactivatePublicOutput(publicFields, params),
    derived: {
      coordPubKeyHash,
      currentDeactivateCommitment,
      messageHashChain,
      inputHash: expectedInputHash,
    },
  };
}

export function evaluateProcessDeactivateMessagesStateTransition(
  rawInput,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  assertSupportedParams(params);
  if (!Array.isArray(rawInput.processOneWitnesses) || rawInput.processOneWitnesses.length !== params.messageBatchSize) {
    throw new Error(`processOneWitnesses must contain ${params.messageBatchSize} witnesses`);
  }

  const input = {
    coordPrivKey: parseBigInt(rawInput.coordPrivKey, 'coordPrivKey'),
    currentStateRoot: parseBigInt(rawInput.currentStateRoot, 'currentStateRoot'),
    currentActiveStateRoot: parseBigInt(rawInput.currentActiveStateRoot, 'currentActiveStateRoot'),
    currentDeactivateRoot: parseBigInt(rawInput.currentDeactivateRoot, 'currentDeactivateRoot'),
    expectedPollId: parseBigInt(rawInput.expectedPollId, 'expectedPollId'),
    deactivateIndex0: parseBigInt(rawInput.deactivateIndex0, 'deactivateIndex0'),
    newActiveStateRoot:
      rawInput.newActiveStateRoot === undefined
        ? undefined
        : parseBigInt(rawInput.newActiveStateRoot, 'newActiveStateRoot'),
    newDeactivateRoot:
      rawInput.newDeactivateRoot === undefined
        ? undefined
        : parseBigInt(rawInput.newDeactivateRoot, 'newDeactivateRoot'),
  };

  let activeRoot = input.currentActiveStateRoot;
  let deactivateRoot = input.currentDeactivateRoot;
  const transitions = [];
  for (let i = 0; i < params.messageBatchSize; i += 1) {
    const evaluated = evaluateProcessDeactivateOne(rawInput.processOneWitnesses[i], params);
    expectEqual(evaluated.input.coordPrivKey, input.coordPrivKey, `processOneWitnesses[${i}].coordPrivKey`);
    expectEqual(evaluated.input.currentStateRoot, input.currentStateRoot, `processOneWitnesses[${i}].currentStateRoot`);
    expectEqual(evaluated.input.currentActiveStateRoot, activeRoot, `processOneWitnesses[${i}].currentActiveStateRoot`);
    expectEqual(evaluated.input.currentDeactivateRoot, deactivateRoot, `processOneWitnesses[${i}].currentDeactivateRoot`);
    expectEqual(evaluated.input.expectedPollId, input.expectedPollId, `processOneWitnesses[${i}].expectedPollId`);
    expectEqual(
      evaluated.input.deactivateIndex,
      input.deactivateIndex0 + BigInt(i),
      `processOneWitnesses[${i}].deactivateIndex`,
    );
    transitions.push(evaluated);
    activeRoot = evaluated.derived.newActiveStateRoot;
    deactivateRoot = evaluated.derived.newDeactivateRoot;
  }

  if (input.newActiveStateRoot !== undefined) {
    expectEqual(activeRoot, input.newActiveStateRoot, 'newActiveStateRoot');
  }
  if (input.newDeactivateRoot !== undefined) {
    expectEqual(deactivateRoot, input.newDeactivateRoot, 'newDeactivateRoot');
  }

  return {
    params,
    input,
    transitions,
    derived: {
      newActiveStateRoot: activeRoot,
      newDeactivateRoot: deactivateRoot,
    },
  };
}

export function evaluateProcessDeactivateMessagesStateful(
  rawInput,
  params = SMALL_PROCESS_DEACTIVATE_PARAMS,
) {
  const boundary = evaluateProcessDeactivateMessages(rawInput, params);
  const state = evaluateProcessDeactivateMessagesStateTransition(rawInput, params);

  expectEqual(state.input.currentActiveStateRoot, boundary.input.currentActiveStateRoot, 'state.currentActiveStateRoot');
  expectEqual(state.input.currentDeactivateRoot, boundary.input.currentDeactivateRoot, 'state.currentDeactivateRoot');
  expectEqual(state.input.currentStateRoot, boundary.input.currentStateRoot, 'state.currentStateRoot');
  expectEqual(state.input.expectedPollId, boundary.input.expectedPollId, 'state.expectedPollId');
  expectEqual(state.derived.newDeactivateRoot, boundary.input.newDeactivateRoot, 'newDeactivateRoot');

  const newDeactivateCommitment = hashLeftRight(
    state.derived.newActiveStateRoot,
    state.derived.newDeactivateRoot,
  );
  expectEqual(newDeactivateCommitment, boundary.input.newDeactivateCommitment, 'newDeactivateCommitment');

  for (let i = 0; i < params.messageBatchSize; i += 1) {
    const expectedIsEmpty = boundary.input.msgs[i][0] === 0n ? 1n : 0n;
    expectEqual(
      state.transitions[i].input.isEmptyMsg,
      expectedIsEmpty,
      `processOneWitnesses[${i}].isEmptyMsg`,
    );
  }
  const messageCommands = [];
  for (let i = 0; i < params.messageBatchSize; i += 1) {
    messageCommands.push(expectProcessOneMessageCommand(i, rawInput, state.transitions[i]));
  }

  return {
    params,
    boundary,
    state,
    publicFields: boundary.publicFields,
    publicOutput: boundary.publicOutput,
    derived: {
      newActiveStateRoot: state.derived.newActiveStateRoot,
      newDeactivateRoot: state.derived.newDeactivateRoot,
      newDeactivateCommitment,
      messageCommands,
    },
  };
}
