import { SMALL_PROCESS_DEACTIVATE_PARAMS, TREE_ARITY } from '../constants.mjs';
import { deepMapBigInt, parseBigInt } from '../compat/encoding.mjs';
import { babyjubAdd, babyjubScalarMul, bn254Sub, buildBabyjubPoseidonSignatureWitness } from '../compat/babyjub.mjs';
import { hash10, hash5, hashLeftRight } from '../compat/poseidon.mjs';
import { quinaryInclusionRoot } from '../compat/quinary-tree.mjs';

const STATE_LEAF_LENGTH = 10;
const MAX_STATE_INDEX = TREE_ARITY ** SMALL_PROCESS_DEACTIVATE_PARAMS.stateTreeDepth - 1;

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

function boolToBigInt(value) {
  return value ? 1n : 0n;
}

export function elGamalDecryptPoint(c1, c2, coordPrivKey) {
  expectVectorShape(c1, 2, 'c1');
  expectVectorShape(c2, 2, 'c2');
  const parsedC1 = deepMapBigInt(c1);
  const parsedC2 = deepMapBigInt(c2);
  const c1x = babyjubScalarMul(parsedC1, coordPrivKey);
  const c1xInverse = [bn254Sub(0n, c1x[0]), c1x[1]];
  const decryptedPoint = babyjubAdd(c1xInverse, parsedC2);
  return {
    c1x,
    c1xInverse,
    decryptedPoint,
    isOdd: decryptedPoint[0] & 1n,
  };
}

export function evaluateProcessDeactivateOne(rawInput, params = SMALL_PROCESS_DEACTIVATE_PARAMS) {
  if (params.stateTreeDepth !== 2 || params.deactivateTreeDepth !== 4) {
    throw new Error('only AMACI ProcessDeactivate ProcessOne depths (2, 4) are supported');
  }
  expectVectorShape(rawInput.c1, 2, 'c1');
  expectVectorShape(rawInput.c2, 2, 'c2');
  expectVectorShape(rawInput.stateLeaf, STATE_LEAF_LENGTH, 'stateLeaf');
  expectVectorShape(rawInput.cmdSigR8, 2, 'cmdSigR8');
  expectVectorShape(rawInput.packedCmd, 3, 'packedCmd');
  expectPathShape(rawInput.stateLeafPathElements, params.stateTreeDepth, 'stateLeafPathElements');
  expectPathShape(
    rawInput.activeStateLeafPathElements,
    params.stateTreeDepth,
    'activeStateLeafPathElements',
  );
  expectPathShape(
    rawInput.deactivateLeafPathElements,
    params.deactivateTreeDepth,
    'deactivateLeafPathElements',
  );

  const input = {
    isEmptyMsg: parseBool(rawInput.isEmptyMsg, 'isEmptyMsg'),
    coordPrivKey: parseBigInt(rawInput.coordPrivKey, 'coordPrivKey'),
    currentStateRoot: parseBigInt(rawInput.currentStateRoot, 'currentStateRoot'),
    c1: deepMapBigInt(rawInput.c1),
    c2: deepMapBigInt(rawInput.c2),
    currentActiveStateRoot: parseBigInt(rawInput.currentActiveStateRoot, 'currentActiveStateRoot'),
    currentDeactivateRoot: parseBigInt(rawInput.currentDeactivateRoot, 'currentDeactivateRoot'),
    stateLeaf: deepMapBigInt(rawInput.stateLeaf),
    stateLeafPathElements: deepMapBigInt(rawInput.stateLeafPathElements),
    activeStateLeafPathElements: deepMapBigInt(rawInput.activeStateLeafPathElements),
    currentActiveState: parseBigInt(rawInput.currentActiveState, 'currentActiveState'),
    newActiveState: parseBigInt(rawInput.newActiveState, 'newActiveState'),
    cmdStateIndex: parseBigInt(rawInput.cmdStateIndex, 'cmdStateIndex'),
    cmdPollId: parseBigInt(rawInput.cmdPollId, 'cmdPollId'),
    cmdSigR8: deepMapBigInt(rawInput.cmdSigR8),
    cmdSigS: parseBigInt(rawInput.cmdSigS, 'cmdSigS'),
    packedCmd: deepMapBigInt(rawInput.packedCmd),
    expectedPollId: parseBigInt(rawInput.expectedPollId, 'expectedPollId'),
    deactivateIndex: parseBigInt(rawInput.deactivateIndex, 'deactivateIndex'),
    deactivateLeafPathElements: deepMapBigInt(rawInput.deactivateLeafPathElements),
    newActiveStateRoot:
      rawInput.newActiveStateRoot === undefined
        ? undefined
        : parseBigInt(rawInput.newActiveStateRoot, 'newActiveStateRoot'),
    newDeactivateRoot:
      rawInput.newDeactivateRoot === undefined
        ? undefined
        : parseBigInt(rawInput.newDeactivateRoot, 'newDeactivateRoot'),
  };

  const signatureWitness = buildBabyjubPoseidonSignatureWitness({
    pubKey: input.stateLeaf.slice(0, 2),
    r8: input.cmdSigR8,
    s: input.cmdSigS,
    preimage: input.packedCmd,
  });
  const currentStateDecrypt = elGamalDecryptPoint(
    input.stateLeaf.slice(5, 7),
    input.stateLeaf.slice(7, 9),
    input.coordPrivKey,
  );
  const validPollId = input.cmdPollId === input.expectedPollId;
  const valid = signatureWitness.valid === 1n && currentStateDecrypt.isOdd === 0n && validPollId;
  const newStateDecrypt = elGamalDecryptPoint(input.c1, input.c2, input.coordPrivKey);
  expectEqual(boolToBigInt(valid), 1n - newStateDecrypt.isOdd, 'valid/decryptIsActive');

  const stateIndex =
    input.cmdStateIndex >= 0n && input.cmdStateIndex <= BigInt(MAX_STATE_INDEX)
      ? input.cmdStateIndex
      : BigInt(MAX_STATE_INDEX);
  const stateLeafHash = hash10(input.stateLeaf);
  const currentStateRoot = quinaryInclusionRoot(
    stateLeafHash,
    input.stateLeafPathElements,
    stateIndex,
  );
  expectEqual(currentStateRoot, input.currentStateRoot, 'currentStateRoot');

  if (input.newActiveState === 0n) {
    throw new Error('newActiveState must be non-zero');
  }
  const currentActiveStateRoot = quinaryInclusionRoot(
    input.currentActiveState,
    input.activeStateLeafPathElements,
    stateIndex,
  );
  expectEqual(currentActiveStateRoot, input.currentActiveStateRoot, 'currentActiveStateRoot');
  const newActiveStateLeaf = valid ? input.newActiveState : input.currentActiveState;
  const newActiveStateRoot = quinaryInclusionRoot(
    newActiveStateLeaf,
    input.activeStateLeafPathElements,
    stateIndex,
  );
  if (input.newActiveStateRoot !== undefined) {
    expectEqual(newActiveStateRoot, input.newActiveStateRoot, 'newActiveStateRoot');
  }

  const currentDeactivateRoot = quinaryInclusionRoot(
    0n,
    input.deactivateLeafPathElements,
    input.deactivateIndex,
  );
  expectEqual(currentDeactivateRoot, input.currentDeactivateRoot, 'currentDeactivateRoot');

  const sharedKey = babyjubScalarMul(input.stateLeaf.slice(0, 2), input.coordPrivKey);
  const sharedKeyHash = hashLeftRight(sharedKey[0], sharedKey[1]);
  const deactivateLeaf = hash5([...input.c1, ...input.c2, sharedKeyHash]);
  const newDeactivateLeaf = input.isEmptyMsg === 1n ? 0n : deactivateLeaf;
  const newDeactivateRoot = quinaryInclusionRoot(
    newDeactivateLeaf,
    input.deactivateLeafPathElements,
    input.deactivateIndex,
  );
  if (input.newDeactivateRoot !== undefined) {
    expectEqual(newDeactivateRoot, input.newDeactivateRoot, 'newDeactivateRoot');
  }

  return {
    params,
    input,
    derived: {
      signatureWitness,
      signatureValid: signatureWitness.valid,
      currentStateDecrypt,
      newStateDecrypt,
      validPollId: boolToBigInt(validPollId),
      valid: boolToBigInt(valid),
      stateIndex,
      stateLeafHash,
      sharedKey,
      sharedKeyHash,
      deactivateLeaf,
      newActiveStateLeaf,
      newActiveStateRoot,
      newDeactivateLeaf,
      newDeactivateRoot,
    },
  };
}
