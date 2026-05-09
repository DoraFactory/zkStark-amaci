import { SMALL_PROCESS_MESSAGES_PARAMS, TREE_ARITY } from '../constants.mjs';
import { deepMapBigInt, parseBigInt } from '../compat/encoding.mjs';
import { buildElGamalDecryptWitness } from '../compat/babyjub.mjs';
import { bn254, poseidonPermutationBn254 } from '../compat/poseidon-bn254.mjs';
import { hash10 } from '../compat/poseidon.mjs';
import { quinaryInclusionRoot, zeroRoot } from '../compat/quinary-tree.mjs';

const STATE_LEAF_LENGTH = 10;
const MESSAGE_LENGTH = 10;
const DECRYPTED_COMMAND_LENGTH = 7;
const PADDED_DECRYPTED_COMMAND_LENGTH = 9;
const MAX_STATE_INDEX = TREE_ARITY ** SMALL_PROCESS_MESSAGES_PARAMS.stateTreeDepth - 1;
const U32_MODULUS = 1n << 32n;
const TWO_POW_128 = 1n << 128n;
const MAX_VALID_VOTE_WEIGHT = 147946756881789319005730692170996259609n;
const CIRCOM_UINT32_TO_96_HIGH_FACTOR = 18446744073709552000n;

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

function expectPathShape(path, depth, label) {
  if (!Array.isArray(path) || path.length !== depth) {
    throw new Error(`${label} must contain ${depth} levels`);
  }
  for (let i = 0; i < depth; i += 1) {
    expectVectorShape(path[i], TREE_ARITY - 1, `${label}[${i}]`);
  }
}

function parseBool(value, label) {
  const n = parseBigInt(value, label);
  if (n !== 0n && n !== 1n) {
    throw new Error(`${label} must be 0 or 1`);
  }
  return n;
}

function parseU32(value, label) {
  const n = parseBigInt(value, label);
  if (n < 0n || n >= U32_MODULUS) {
    throw new Error(`${label} must fit in 32 bits`);
  }
  return n;
}

function expectU32(value, label) {
  if (value < 0n || value >= U32_MODULUS) {
    throw new Error(`${label} must fit in 32 bits`);
  }
  return value;
}

function boolToBigInt(value) {
  return value ? 1n : 0n;
}

function processOneCost(isQuadraticCost, voteWeight) {
  return isQuadraticCost === 1n ? voteWeight * voteWeight : voteWeight;
}

function selectByValidity(isValid, ifInvalid, ifValid) {
  return isValid === 1n ? ifValid : ifInvalid;
}

function stateLeafVoteRoot(stateLeaf) {
  return stateLeaf[3];
}

function bn254Sub(left, right) {
  return bn254(parseBigInt(left) - parseBigInt(right));
}

function bn254AddValue(left, right) {
  return bn254(parseBigInt(left) + parseBigInt(right));
}

export function poseidonDecryptWithoutCheck7(message, sharedKey, nonce = 0n) {
  expectVectorShape(message, MESSAGE_LENGTH, 'msg');
  expectVectorShape(sharedKey, 2, 'sharedKey');
  const ciphertext = deepMapBigInt(message);
  const key = deepMapBigInt(sharedKey);
  const decrypted = [];
  let state = poseidonPermutationBn254([
    0n,
    key[0],
    key[1],
    parseBigInt(nonce, 'nonce') + BigInt(DECRYPTED_COMMAND_LENGTH) * TWO_POW_128,
  ]);

  for (let i = 0; i < 3; i += 1) {
    for (let j = 0; j < 3; j += 1) {
      decrypted.push(bn254Sub(ciphertext[i * 3 + j], state[j + 1]));
    }
    state = poseidonPermutationBn254([
      state[0],
      ciphertext[i * 3],
      ciphertext[i * 3 + 1],
      ciphertext[i * 3 + 2],
    ]);
  }

  return decrypted.slice(0, DECRYPTED_COMMAND_LENGTH);
}

export function poseidonEncryptWithoutCheck7(decryptedCommand, sharedKey, nonce = 0n) {
  expectVectorShape(decryptedCommand, DECRYPTED_COMMAND_LENGTH, 'decryptedCommand');
  expectVectorShape(sharedKey, 2, 'sharedKey');
  const plaintext = [
    ...deepMapBigInt(decryptedCommand),
    ...Array.from({ length: PADDED_DECRYPTED_COMMAND_LENGTH - DECRYPTED_COMMAND_LENGTH }, () => 0n),
  ];
  const key = deepMapBigInt(sharedKey);
  const ciphertext = [];
  let state = poseidonPermutationBn254([
    0n,
    key[0],
    key[1],
    parseBigInt(nonce, 'nonce') + BigInt(DECRYPTED_COMMAND_LENGTH) * TWO_POW_128,
  ]);

  for (let i = 0; i < 3; i += 1) {
    for (let j = 0; j < 3; j += 1) {
      ciphertext.push(bn254AddValue(plaintext[i * 3 + j], state[j + 1]));
    }
    state = poseidonPermutationBn254([
      state[0],
      ciphertext[i * 3],
      ciphertext[i * 3 + 1],
      ciphertext[i * 3 + 2],
    ]);
  }
  ciphertext.push(0n);
  return ciphertext;
}

export function unpackCommandData(packedData) {
  const packed = parseBigInt(packedData, 'packedCommand[0]');
  return {
    pollId: (packed >> 192n) & (U32_MODULUS - 1n),
    voteWeightHigh: (packed >> 160n) & (U32_MODULUS - 1n),
    voteWeightMid: (packed >> 128n) & (U32_MODULUS - 1n),
    voteWeightLow: (packed >> 96n) & (U32_MODULUS - 1n),
    voteOptionIndex: (packed >> 64n) & (U32_MODULUS - 1n),
    stateIndex: (packed >> 32n) & (U32_MODULUS - 1n),
    nonce: packed & (U32_MODULUS - 1n),
  };
}

export function splitCommandVoteWeight(voteWeight) {
  const value = parseBigInt(voteWeight, 'cmdNewVoteWeight');
  const high = value / CIRCOM_UINT32_TO_96_HIGH_FACTOR;
  const highRemainder = value % CIRCOM_UINT32_TO_96_HIGH_FACTOR;
  const mid = highRemainder / U32_MODULUS;
  const low = highRemainder % U32_MODULUS;
  expectU32(high, 'cmdNewVoteWeight.high32');
  expectU32(mid, 'cmdNewVoteWeight.mid32');
  expectU32(low, 'cmdNewVoteWeight.low32');
  return { high, mid, low };
}

export function packCommandData({
  pollId,
  newVoteWeight,
  voteOptionIndex,
  stateIndex,
  nonce,
}) {
  const { high, mid, low } = splitCommandVoteWeight(newVoteWeight);
  return (
    (expectU32(parseBigInt(pollId, 'pollId'), 'pollId') << 192n) +
    (high << 160n) +
    (mid << 128n) +
    (low << 96n) +
    (expectU32(parseBigInt(voteOptionIndex, 'voteOptionIndex'), 'voteOptionIndex') << 64n) +
    (expectU32(parseBigInt(stateIndex, 'stateIndex'), 'stateIndex') << 32n) +
    expectU32(parseBigInt(nonce, 'nonce'), 'nonce')
  );
}

function reconstructedVoteWeight(unpacked) {
  return (
    unpacked.voteWeightLow +
    unpacked.voteWeightMid * U32_MODULUS +
    unpacked.voteWeightHigh * CIRCOM_UINT32_TO_96_HIGH_FACTOR
  );
}

export function buildProcessOneNewStateLeaf(input, derived) {
  const { isValid } = derived;
  return [
    selectByValidity(isValid, input.stateLeaf[0], input.cmdNewPubKey[0]),
    selectByValidity(isValid, input.stateLeaf[1], input.cmdNewPubKey[1]),
    selectByValidity(isValid, input.stateLeaf[2], derived.newBalance),
    selectByValidity(isValid, input.stateLeaf[3], derived.newVoteOptionRoot),
    selectByValidity(isValid, input.stateLeaf[4], derived.newSlNonce),
    input.stateLeaf[5],
    input.stateLeaf[6],
    input.stateLeaf[7],
    input.stateLeaf[8],
    0n,
  ];
}

export function evaluateProcessOneStateTransition(rawInput, params = SMALL_PROCESS_MESSAGES_PARAMS) {
  if (params.stateTreeDepth !== 2 || params.voteOptionTreeDepth !== 1) {
    throw new Error('only AMACI ProcessOne state transition for depths (2, 1) is supported');
  }
  expectVectorShape(rawInput.stateLeaf, STATE_LEAF_LENGTH, 'stateLeaf');
  expectVectorShape(rawInput.msg, MESSAGE_LENGTH, 'msg');
  expectVectorShape(rawInput.sharedKey, 2, 'sharedKey');
  expectVectorShape(rawInput.decryptedCommand, 7, 'decryptedCommand');
  expectVectorShape(rawInput.packedCommand, 3, 'packedCommand');
  expectVectorShape(rawInput.cmdSigR8, 2, 'cmdSigR8');
  expectVectorShape(rawInput.cmdNewPubKey, 2, 'cmdNewPubKey');
  expectPathShape(rawInput.stateLeafPathElements, params.stateTreeDepth, 'stateLeafPathElements');
  expectPathShape(
    rawInput.activeStateLeafPathElements,
    params.stateTreeDepth,
    'activeStateLeafPathElements',
  );
  expectPathShape(
    rawInput.currentVoteWeightsPathElements,
    params.voteOptionTreeDepth,
    'currentVoteWeightsPathElements',
  );

  const input = {
    isQuadraticCost: parseBool(rawInput.isQuadraticCost, 'isQuadraticCost'),
    coordPrivKey: parseBigInt(rawInput.coordPrivKey, 'coordPrivKey'),
    numSignUps: parseU32(rawInput.numSignUps, 'numSignUps'),
    maxVoteOptions: parseU32(rawInput.maxVoteOptions, 'maxVoteOptions'),
    expectedPollId: parseU32(rawInput.expectedPollId, 'expectedPollId'),
    isSignatureValid: parseBool(rawInput.isSignatureValid, 'isSignatureValid'),
    isDecryptionActive: parseBool(rawInput.isDecryptionActive, 'isDecryptionActive'),
    msg: deepMapBigInt(rawInput.msg),
    sharedKey: deepMapBigInt(rawInput.sharedKey),
    decryptedCommand: deepMapBigInt(rawInput.decryptedCommand),
    packedCommand: deepMapBigInt(rawInput.packedCommand),
    cmdSalt: parseBigInt(rawInput.cmdSalt, 'cmdSalt'),
    cmdSigR8: deepMapBigInt(rawInput.cmdSigR8),
    cmdSigS: parseBigInt(rawInput.cmdSigS, 'cmdSigS'),
    currentStateRoot: parseBigInt(rawInput.currentStateRoot, 'currentStateRoot'),
    activeStateRoot: parseBigInt(rawInput.activeStateRoot, 'activeStateRoot'),
    stateLeaf: deepMapBigInt(rawInput.stateLeaf),
    stateLeafPathElements: deepMapBigInt(rawInput.stateLeafPathElements),
    activeStateLeaf: parseBigInt(rawInput.activeStateLeaf, 'activeStateLeaf'),
    activeStateLeafPathElements: deepMapBigInt(rawInput.activeStateLeafPathElements),
    currentVoteWeight: parseBigInt(rawInput.currentVoteWeight, 'currentVoteWeight'),
    currentVoteWeightsPathElements: deepMapBigInt(rawInput.currentVoteWeightsPathElements),
    isValid: parseBool(rawInput.isValid, 'isValid'),
    cmdStateIndex: parseBigInt(rawInput.cmdStateIndex, 'cmdStateIndex'),
    cmdVoteOptionIndex: parseBigInt(rawInput.cmdVoteOptionIndex, 'cmdVoteOptionIndex'),
    cmdNewVoteWeight: parseBigInt(rawInput.cmdNewVoteWeight, 'cmdNewVoteWeight'),
    cmdNonce: parseU32(rawInput.cmdNonce, 'cmdNonce'),
    cmdPollId: parseU32(rawInput.cmdPollId, 'cmdPollId'),
    cmdNewPubKey: deepMapBigInt(rawInput.cmdNewPubKey),
    newBalance: parseBigInt(rawInput.newBalance, 'newBalance'),
    newSlNonce: parseBigInt(rawInput.newSlNonce, 'newSlNonce'),
    newStateRoot:
      rawInput.newStateRoot === undefined
        ? undefined
        : parseBigInt(rawInput.newStateRoot, 'newStateRoot'),
  };

  if (input.numSignUps > BigInt(MAX_STATE_INDEX + 1)) {
    throw new Error('numSignUps exceeds state tree capacity');
  }
  if (input.maxVoteOptions > BigInt(TREE_ARITY ** params.voteOptionTreeDepth)) {
    throw new Error('maxVoteOptions exceeds vote option tree capacity');
  }

  const decryptedFromMessage = poseidonDecryptWithoutCheck7(input.msg, input.sharedKey);
  for (let i = 0; i < DECRYPTED_COMMAND_LENGTH; i += 1) {
    expectEqual(input.decryptedCommand[i], decryptedFromMessage[i], `decryptedCommand[${i}]`);
  }

  expectEqual(input.packedCommand[0], input.decryptedCommand[0], 'packedCommand[0]');
  expectEqual(input.packedCommand[1], input.decryptedCommand[1], 'packedCommand[1]');
  expectEqual(input.packedCommand[2], input.decryptedCommand[2], 'packedCommand[2]');
  expectEqual(input.cmdSalt, input.decryptedCommand[3], 'cmdSalt');
  expectEqual(input.cmdSigR8[0], input.decryptedCommand[4], 'cmdSigR8[0]');
  expectEqual(input.cmdSigR8[1], input.decryptedCommand[5], 'cmdSigR8[1]');
  expectEqual(input.cmdSigS, input.decryptedCommand[6], 'cmdSigS');

  const unpackedCommand = unpackCommandData(input.packedCommand[0]);
  expectEqual(input.cmdPollId, unpackedCommand.pollId, 'cmdPollId');
  expectEqual(input.cmdNewVoteWeight, reconstructedVoteWeight(unpackedCommand), 'cmdNewVoteWeight');
  expectEqual(input.cmdVoteOptionIndex, unpackedCommand.voteOptionIndex, 'cmdVoteOptionIndex');
  expectEqual(input.cmdStateIndex, unpackedCommand.stateIndex, 'cmdStateIndex');
  expectEqual(input.cmdNonce, unpackedCommand.nonce, 'cmdNonce');
  expectEqual(input.cmdNewPubKey[0], input.packedCommand[1], 'cmdNewPubKey[0]');
  expectEqual(input.cmdNewPubKey[1], input.packedCommand[2], 'cmdNewPubKey[1]');

  const currentCost = processOneCost(input.isQuadraticCost, input.currentVoteWeight);
  const newCost = processOneCost(input.isQuadraticCost, input.cmdNewVoteWeight);
  const availableVoiceCredits = input.stateLeaf[2] + currentCost;
  const sufficientVoiceCredits = availableVoiceCredits >= newCost;
  const stateDecrypt = buildElGamalDecryptWitness({
    privKey: input.coordPrivKey,
    c1: [input.stateLeaf[5], input.stateLeaf[6]],
    c2: [input.stateLeaf[7], input.stateLeaf[8]],
  });
  const computedIsDecryptionActive = 1n - stateDecrypt.isOdd;
  expectEqual(input.isDecryptionActive, computedIsDecryptionActive, 'isDecryptionActive');
  const messageValid =
    input.isSignatureValid === 1n &&
    input.cmdStateIndex <= input.numSignUps &&
    input.cmdStateIndex <= BigInt(MAX_STATE_INDEX) &&
    input.cmdVoteOptionIndex < input.maxVoteOptions &&
    input.cmdNonce === input.stateLeaf[4] + 1n &&
    input.cmdPollId === input.expectedPollId &&
    input.cmdNewVoteWeight <= MAX_VALID_VOTE_WEIGHT &&
    sufficientVoiceCredits;
  const computedIsValid = boolToBigInt(
    messageValid && input.isDecryptionActive === 1n && input.activeStateLeaf === 0n,
  );
  expectEqual(input.isValid, computedIsValid, 'isValid');

  const computedNewBalance = availableVoiceCredits - newCost;
  const computedNewSlNonce = input.cmdNonce;
  if (computedIsValid === 1n) {
    expectEqual(input.newBalance, computedNewBalance, 'newBalance');
    expectEqual(input.newSlNonce, computedNewSlNonce, 'newSlNonce');
  }

  const stateIndex = selectByValidity(computedIsValid, BigInt(MAX_STATE_INDEX), input.cmdStateIndex);
  const voteOptionIndex = selectByValidity(computedIsValid, 0n, input.cmdVoteOptionIndex);
  const currentVoteRoot = stateLeafVoteRoot(input.stateLeaf) === 0n
    ? zeroRoot(params.voteOptionTreeDepth)
    : stateLeafVoteRoot(input.stateLeaf);

  const stateLeafHash = hash10(input.stateLeaf);
  const derivedCurrentStateRoot = quinaryInclusionRoot(
    stateLeafHash,
    input.stateLeafPathElements,
    stateIndex,
  );
  expectEqual(derivedCurrentStateRoot, input.currentStateRoot, 'currentStateRoot');

  const derivedActiveStateRoot = quinaryInclusionRoot(
    input.activeStateLeaf,
    input.activeStateLeafPathElements,
    stateIndex,
  );
  expectEqual(derivedActiveStateRoot, input.activeStateRoot, 'activeStateRoot');

  const derivedCurrentVoteRoot = quinaryInclusionRoot(
    input.currentVoteWeight,
    input.currentVoteWeightsPathElements,
    voteOptionIndex,
  );
  expectEqual(derivedCurrentVoteRoot, currentVoteRoot, 'currentVoteRoot');

  const updatedVoteWeight = selectByValidity(
    computedIsValid,
    input.currentVoteWeight,
    input.cmdNewVoteWeight,
  );
  const newVoteOptionRoot = quinaryInclusionRoot(
    updatedVoteWeight,
    input.currentVoteWeightsPathElements,
    voteOptionIndex,
  );

  const provisionalDerived = {
    isValid: computedIsValid,
    messageValid: boolToBigInt(messageValid),
    currentCost,
    newCost,
    availableVoiceCredits,
    newBalance: computedNewBalance,
    newSlNonce: computedNewSlNonce,
    stateIndex,
    voteOptionIndex,
    currentVoteRoot,
    updatedVoteWeight,
    newVoteOptionRoot,
  };
  const newStateLeaf = buildProcessOneNewStateLeaf(input, provisionalDerived);
  const newStateLeafHash = hash10(newStateLeaf);
  const newStateRoot = quinaryInclusionRoot(
    newStateLeafHash,
    input.stateLeafPathElements,
    stateIndex,
  );
  if (input.newStateRoot !== undefined) {
    expectEqual(newStateRoot, input.newStateRoot, 'newStateRoot');
  }

  return {
    params,
    input,
    derived: {
      ...provisionalDerived,
      stateLeafHash,
      activeStateLeaf: input.activeStateLeaf,
      stateDecrypt,
      unpackedCommand,
      currentVoteWeight: input.currentVoteWeight,
      newStateLeaf,
      newStateLeafHash,
      newStateRoot,
    },
  };
}
