import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN,
  ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN,
  ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN,
  ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN,
  TREE_ARITY,
} from '../src/constants.mjs';
import { starkPointAdd, starkPublicKeyPoint, starkScalarMul } from '../src/stark-native-crypto.mjs';
import {
  nativeHash5,
  nativeHashFelts,
  nativeHashPoint,
} from '../src/native-hash.mjs';
import { evaluateAddNewKey } from '../src/add-new-key/add-new-key.mjs';
import {
  buildNativeCairoAddNewKeyInput,
  serializeNativeCairoAddNewKeyExecutableArgs,
} from '../src/add-new-key/cairo-input.mjs';

function quinaryLayers(leaves, depth) {
  let level = leaves.map(BigInt);
  const layers = [level];
  for (let d = 0; d < depth; d += 1) {
    const next = [];
    for (let i = 0; i < level.length; i += TREE_ARITY) {
      next.push(nativeHash5(level.slice(i, i + TREE_ARITY), `tree.level${d}.${i}`));
    }
    layers.push(next);
    level = next;
  }
  return layers;
}

function pathFor(leaves, depth, index) {
  const layers = quinaryLayers(leaves, depth);
  let cursor = index;
  const path = [];
  for (let level = 0; level < depth; level += 1) {
    const idx = cursor % TREE_ARITY;
    const groupStart = cursor - idx;
    const siblings = [];
    for (let i = 0; i < TREE_ARITY; i += 1) {
      if (i !== idx) {
        siblings.push(layers[level][groupStart + i]);
      }
    }
    path.push(siblings);
    cursor = Math.floor(cursor / TREE_ARITY);
  }
  return {
    root: layers[depth][0],
    path,
  };
}

function decimalize(value) {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map(decimalize);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, decimalize(val)]));
  }
  return value;
}

function buildFixture() {
  const coordPubKey = starkPublicKeyPoint(5n);
  const oldPrivateKey = 7n;
  const pollId = 77n;
  const c1 = starkPublicKeyPoint(2n);
  const c2 = starkPublicKeyPoint(3n);
  const randomVal = 11n;
  const randomBase = starkPublicKeyPoint(randomVal);
  const randomCoordPubKey = starkScalarMul(coordPubKey, randomVal);
  const d1 = starkPointAdd(randomBase, c1);
  const d2 = starkPointAdd(randomCoordPubKey, c2);
  const sharedKey = starkScalarMul(coordPubKey, oldPrivateKey);
  const sharedKeyHash = nativeHashPoint(sharedKey, 'sharedKey');
  const c1Hash = nativeHashPoint(c1, 'c1');
  const c2Hash = nativeHashPoint(c2, 'c2');
  const deactivateLeaf = nativeHashFelts(
    [ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN, c1Hash, c2Hash, sharedKeyHash],
    'deactivateLeaf',
  );
  const deactivateIndex = 42;
  const leaves = Array.from({ length: TREE_ARITY ** 4 }, () => 0n);
  leaves[deactivateIndex] = deactivateLeaf;
  const deactivateTree = pathFor(leaves, 4, deactivateIndex);
  const nullifier = nativeHashFelts(
    [ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN, oldPrivateKey, pollId],
    'nullifier',
  );
  const newPubKey = starkPublicKeyPoint(13n);
  const coordPubKeyHash = nativeHashPoint(coordPubKey, 'coordPubKey');
  const d1Hash = nativeHashPoint(d1, 'd1');
  const d2Hash = nativeHashPoint(d2, 'd2');
  const rerandomizeBindingHash = nativeHashFelts(
    [ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN, coordPubKeyHash, c1Hash, c2Hash, d1Hash, d2Hash],
    'rerandomizeBinding',
  );
  const newPubKeyHash = nativeHashPoint(newPubKey, 'newPubKey');
  const inputHash = nativeHashFelts([
    ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN,
    deactivateTree.root,
    coordPubKeyHash,
    nullifier,
    c1Hash,
    c2Hash,
    sharedKeyHash,
    deactivateLeaf,
    d1Hash,
    d2Hash,
    rerandomizeBindingHash,
    newPubKeyHash,
    pollId,
  ], 'addNewKeyInputHash');

  return decimalize({
    deactivateRoot: deactivateTree.root,
    coordPubKey,
    deactivateIndex,
    deactivateLeaf,
    c1,
    c2,
    randomVal,
    d1,
    d2,
    deactivateLeafPathElements: deactivateTree.path,
    nullifier,
    oldPrivateKey,
    newPubKey,
    pollId,
    inputHash,
  });
}

test('validates AMACI AddNewKey relation', () => {
  const input = buildFixture();
  const result = evaluateAddNewKey(input);

  assert.equal(result.derived.deactivateLeaf.toString(), input.deactivateLeaf);
  assert.equal(result.derived.deactivateRoot.toString(), input.deactivateRoot);
  assert.equal(result.derived.inputHash.toString(), input.inputHash);
  assert.equal(result.publicFields.inputHash.toString(), input.inputHash);
});

test('builds native public hash arguments for AddNewKey', () => {
  const input = buildFixture();
  const evaluated = evaluateAddNewKey(input);
  const cairoInput = buildNativeCairoAddNewKeyInput(input, evaluated);
  const args = serializeNativeCairoAddNewKeyExecutableArgs(cairoInput);
  const expectedNativeNullifier = nativeHashFelts([
    ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN,
    evaluated.input.oldPrivateKey,
    evaluated.input.pollId,
  ], 'nullifier');
  const expectedC1Hash = nativeHashPoint(evaluated.input.c1, 'c1');
  const expectedC2Hash = nativeHashPoint(evaluated.input.c2, 'c2');
  const expectedSharedKeyHash = nativeHashPoint(evaluated.derived.sharedKey, 'sharedKey');
  const expectedD1Hash = nativeHashPoint(evaluated.input.d1, 'd1');
  const expectedD2Hash = nativeHashPoint(evaluated.input.d2, 'd2');
  const expectedDeactivateLeafHash = nativeHashFelts([
    ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN,
    expectedC1Hash,
    expectedC2Hash,
    expectedSharedKeyHash,
  ], 'deactivateLeaf');
  const expectedRerandomizeBindingHash = nativeHashFelts([
    ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN,
    cairoInput.publicFields.coord_pub_key_hash,
    expectedC1Hash,
    expectedC2Hash,
    expectedD1Hash,
    expectedD2Hash,
  ], 'rerandomizeBinding');

  assert.equal(cairoInput.public_output.length, 19);
  assert.ok(cairoInput.public_output_labels.includes('hash_scheme'));
  assert.ok(cairoInput.public_output_labels.includes('rerandomize_binding_hash'));
  assert.equal(cairoInput.publicFields.deactivate_root_hash, evaluated.publicFields.deactivateRootHash);
  assert.equal(cairoInput.publicFields.poll_id, evaluated.input.pollId);
  assert.equal(cairoInput.publicFields.nullifier, expectedNativeNullifier);
  assert.equal(cairoInput.publicFields.c1_hash, expectedC1Hash);
  assert.equal(cairoInput.publicFields.c2_hash, expectedC2Hash);
  assert.equal(cairoInput.publicFields.shared_key_hash, expectedSharedKeyHash);
  assert.equal(cairoInput.publicFields.deactivate_leaf_hash, expectedDeactivateLeafHash);
  assert.equal(cairoInput.publicFields.d1_hash, expectedD1Hash);
  assert.equal(cairoInput.publicFields.d2_hash, expectedD2Hash);
  assert.equal(cairoInput.publicFields.rerandomize_binding_hash, expectedRerandomizeBindingHash);
  assert.equal(cairoInput.publicFields.coord_pub_key_hash, evaluated.publicFields.coordPubKeyHash);
  assert.equal(cairoInput.publicFields.new_pub_key_hash, evaluated.publicFields.newPubKeyHash);
  assert.equal(cairoInput.publicFields.input_hash, evaluated.publicFields.inputHash);
  assert.equal(cairoInput.program_input.witness.legacy, undefined);
  assert.equal(cairoInput.program_input.witness.random_base8, undefined);
  assert.notEqual(cairoInput.program_input.witness.random_val, undefined);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
});

test('rejects a tampered AddNewKey re-randomized ciphertext', () => {
  const input = buildFixture();
  input.d1[0] = '1';

  assert.throws(() => evaluateAddNewKey(input), /d1\[0\] mismatch/);
});

test('rejects a tampered AddNewKey deactivate path', () => {
  const input = buildFixture();
  input.deactivateLeafPathElements[0][0] = '1';

  assert.throws(() => evaluateAddNewKey(input), /deactivateRoot mismatch/);
});
