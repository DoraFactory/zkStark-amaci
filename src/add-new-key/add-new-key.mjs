import { SMALL_PROCESS_MESSAGES_PARAMS } from '../constants.mjs';
import { addNewKeyInputHash, deepMapBigInt, parseBigInt } from '../compat/encoding.mjs';
import { BABYJUB_BASE8, babyjubAdd, babyjubScalarMul } from '../compat/babyjub.mjs';
import { hash5, hashLeftRight } from '../compat/poseidon.mjs';
import { quinaryInclusionRoot } from '../compat/quinary-tree.mjs';
import { canonicalAddNewKeyPublicOutput } from '../public-output.mjs';

const DEACTIVATE_TREE_DEPTH_OFFSET = 2;

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
    expectVectorShape(path[i], 4, `${label}[${i}]`);
  }
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch: expected ${expected.toString()}, got ${actual.toString()}`);
  }
}

export function evaluateAddNewKey(rawInput, params = { stateTreeDepth: SMALL_PROCESS_MESSAGES_PARAMS.stateTreeDepth }) {
  if (params.stateTreeDepth !== 2) {
    throw new Error('only AMACI AddNewKey stateTreeDepth=2 is supported in this migration step');
  }
  const deactivateTreeDepth = params.stateTreeDepth + DEACTIVATE_TREE_DEPTH_OFFSET;

  expectVectorShape(rawInput.coordPubKey, 2, 'coordPubKey');
  expectVectorShape(rawInput.c1, 2, 'c1');
  expectVectorShape(rawInput.c2, 2, 'c2');
  expectVectorShape(rawInput.d1, 2, 'd1');
  expectVectorShape(rawInput.d2, 2, 'd2');
  expectVectorShape(rawInput.newPubKey, 2, 'newPubKey');
  expectPathShape(rawInput.deactivateLeafPathElements, deactivateTreeDepth, 'deactivateLeafPathElements');

  const input = {
    deactivateRoot: parseBigInt(rawInput.deactivateRoot, 'deactivateRoot'),
    coordPubKey: deepMapBigInt(rawInput.coordPubKey),
    deactivateIndex: parseBigInt(rawInput.deactivateIndex, 'deactivateIndex'),
    deactivateLeaf: parseBigInt(rawInput.deactivateLeaf, 'deactivateLeaf'),
    c1: deepMapBigInt(rawInput.c1),
    c2: deepMapBigInt(rawInput.c2),
    randomVal: parseBigInt(rawInput.randomVal, 'randomVal'),
    d1: deepMapBigInt(rawInput.d1),
    d2: deepMapBigInt(rawInput.d2),
    deactivateLeafPathElements: deepMapBigInt(rawInput.deactivateLeafPathElements),
    nullifier: parseBigInt(rawInput.nullifier, 'nullifier'),
    oldPrivateKey: parseBigInt(rawInput.oldPrivateKey, 'oldPrivateKey'),
    newPubKey: deepMapBigInt(rawInput.newPubKey),
    pollId: parseBigInt(rawInput.pollId, 'pollId'),
    inputHash: parseBigInt(rawInput.inputHash, 'inputHash'),
  };

  const nullifier = hashLeftRight(input.oldPrivateKey, input.pollId);
  expectEqual(nullifier, input.nullifier, 'nullifier');

  const sharedKey = babyjubScalarMul(input.coordPubKey, input.oldPrivateKey);
  const sharedKeyHash = hashLeftRight(sharedKey[0], sharedKey[1]);
  const deactivateLeaf = hash5([...input.c1, ...input.c2, sharedKeyHash]);
  expectEqual(deactivateLeaf, input.deactivateLeaf, 'deactivateLeaf');

  const deactivateRoot = quinaryInclusionRoot(
    input.deactivateLeaf,
    input.deactivateLeafPathElements,
    input.deactivateIndex,
  );
  expectEqual(deactivateRoot, input.deactivateRoot, 'deactivateRoot');

  const randomBase8 = babyjubScalarMul(BABYJUB_BASE8, input.randomVal);
  const d1 = babyjubAdd(randomBase8, input.c1);
  expectEqual(d1[0], input.d1[0], 'd1[0]');
  expectEqual(d1[1], input.d1[1], 'd1[1]');

  const randomCoordPubKey = babyjubScalarMul(input.coordPubKey, input.randomVal);
  const d2 = babyjubAdd(randomCoordPubKey, input.c2);
  expectEqual(d2[0], input.d2[0], 'd2[0]');
  expectEqual(d2[1], input.d2[1], 'd2[1]');

  const coordPubKeyHash = hashLeftRight(input.coordPubKey[0], input.coordPubKey[1]);
  const newPubKeyHash = hashLeftRight(input.newPubKey[0], input.newPubKey[1]);
  const inputHash = addNewKeyInputHash(
    input.deactivateRoot,
    coordPubKeyHash,
    input.nullifier,
    input.d1[0],
    input.d1[1],
    input.d2[0],
    input.d2[1],
    newPubKeyHash,
    input.pollId,
  );
  expectEqual(inputHash, input.inputHash, 'inputHash');

  const publicFields = {
    deactivateRoot: input.deactivateRoot,
    coordPubKeyHash,
    nullifier: input.nullifier,
    d1: input.d1,
    d2: input.d2,
    newPubKeyHash,
    pollId: input.pollId,
    inputHash: input.inputHash,
  };

  return {
    params: { stateTreeDepth: params.stateTreeDepth, deactivateTreeDepth },
    input,
    publicFields,
    publicOutput: canonicalAddNewKeyPublicOutput(publicFields, params),
    derived: {
      nullifier,
      sharedKey,
      sharedKeyHash,
      deactivateLeaf,
      deactivateRoot,
      randomBase8,
      randomCoordPubKey,
      coordPubKeyHash,
      newPubKeyHash,
      inputHash,
    },
  };
}
