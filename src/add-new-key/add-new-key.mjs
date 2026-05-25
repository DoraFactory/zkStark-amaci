import {
  ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN,
  ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN,
  ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN,
  ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN,
  SMALL_PROCESS_MESSAGES_PARAMS,
} from '../constants.mjs';
import { deepMapBigInt, parseBigInt } from '../encoding.mjs';
import { starkPointAdd, starkPublicKeyPoint, starkScalarMul } from '../stark-native-crypto.mjs';
import {
  nativeHash5,
  nativeHashFelts,
  nativeHashPoint,
  nativeQuinaryInclusionRoot,
} from '../native-hash.mjs';

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

  const nullifier = nativeHashFelts(
    [ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN, input.oldPrivateKey, input.pollId],
    'nullifier',
  );
  expectEqual(nullifier, input.nullifier, 'nullifier');

  const sharedKey = starkScalarMul(input.coordPubKey, input.oldPrivateKey);
  const sharedKeyHash = nativeHashPoint(sharedKey, 'sharedKey');
  const c1Hash = nativeHashPoint(input.c1, 'c1');
  const c2Hash = nativeHashPoint(input.c2, 'c2');
  const deactivateLeaf = nativeHashFelts(
    [ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN, c1Hash, c2Hash, sharedKeyHash],
    'deactivateLeaf',
  );
  expectEqual(deactivateLeaf, input.deactivateLeaf, 'deactivateLeaf');

  const deactivateRoot = nativeQuinaryInclusionRoot(
    input.deactivateLeaf,
    input.deactivateLeafPathElements,
    input.deactivateIndex,
    'deactivateRoot',
  );
  expectEqual(deactivateRoot, input.deactivateRoot, 'deactivateRoot');

  const randomBase = starkPublicKeyPoint(input.randomVal);
  const d1 = starkPointAdd(randomBase, input.c1);
  expectEqual(d1[0], input.d1[0], 'd1[0]');
  expectEqual(d1[1], input.d1[1], 'd1[1]');

  const randomCoordPubKey = starkScalarMul(input.coordPubKey, input.randomVal);
  const d2 = starkPointAdd(randomCoordPubKey, input.c2);
  expectEqual(d2[0], input.d2[0], 'd2[0]');
  expectEqual(d2[1], input.d2[1], 'd2[1]');

  const d1Hash = nativeHashPoint(input.d1, 'd1');
  const d2Hash = nativeHashPoint(input.d2, 'd2');
  const coordPubKeyHash = nativeHashPoint(input.coordPubKey, 'coordPubKey');
  const newPubKeyHash = nativeHashPoint(input.newPubKey, 'newPubKey');
  const rerandomizeBindingHash = nativeHashFelts(
    [ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN, coordPubKeyHash, c1Hash, c2Hash, d1Hash, d2Hash],
    'rerandomizeBinding',
  );
  const inputHash = nativeHashFelts([
    ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN,
    input.deactivateRoot,
    coordPubKeyHash,
    input.nullifier,
    c1Hash,
    c2Hash,
    sharedKeyHash,
    deactivateLeaf,
    d1Hash,
    d2Hash,
    rerandomizeBindingHash,
    newPubKeyHash,
    input.pollId,
  ], 'inputHash');
  expectEqual(inputHash, input.inputHash, 'inputHash');

  const publicFields = {
    deactivateRootHash: input.deactivateRoot,
    coordPubKeyHash,
    nullifier: input.nullifier,
    c1Hash,
    c2Hash,
    sharedKeyHash,
    deactivateLeafHash: deactivateLeaf,
    d1Hash,
    d2Hash,
    rerandomizeBindingHash,
    newPubKeyHash,
    pollId: input.pollId,
    inputHash: input.inputHash,
  };

  return {
    params: { stateTreeDepth: params.stateTreeDepth, deactivateTreeDepth },
    input,
    publicFields,
    derived: {
      nullifier,
      sharedKey,
      sharedKeyHash,
      deactivateLeaf,
      deactivateRoot,
      randomBase,
      randomCoordPubKey,
      coordPubKeyHash,
      c1Hash,
      c2Hash,
      d1Hash,
      d2Hash,
      rerandomizeBindingHash,
      newPubKeyHash,
      inputHash,
    },
  };
}
