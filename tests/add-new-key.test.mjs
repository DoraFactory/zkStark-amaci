import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN, TREE_ARITY } from '../src/constants.mjs';
import { addNewKeyInputHash } from '../src/compat/encoding.mjs';
import { BABYJUB_BASE8, babyjubAdd, babyjubScalarMul } from '../src/compat/babyjub.mjs';
import { hash5, hashLeftRight } from '../src/compat/poseidon.mjs';
import { poseidonManyFelts } from '../src/integrity/hashes.mjs';
import { toStarkFelt } from '../src/tally/native-tally-votes.mjs';
import { evaluateAddNewKey } from '../src/add-new-key/add-new-key.mjs';
import {
  buildCairoAddNewKeyInput,
  buildNativeCairoAddNewKeyInput,
  serializeCairoAddNewKeyExecutableArgs,
  serializeNativeCairoAddNewKeyExecutableArgs,
} from '../src/add-new-key/cairo-input.mjs';

function quinaryLayers(leaves, depth) {
  let level = leaves.map(BigInt);
  const layers = [level];
  for (let d = 0; d < depth; d += 1) {
    const next = [];
    for (let i = 0; i < level.length; i += TREE_ARITY) {
      next.push(hash5(level.slice(i, i + TREE_ARITY)));
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
  const coordPubKey = babyjubScalarMul(BABYJUB_BASE8, 5n);
  const oldPrivateKey = 7n;
  const pollId = 77n;
  const c1 = babyjubScalarMul(BABYJUB_BASE8, 2n);
  const c2 = babyjubScalarMul(BABYJUB_BASE8, 3n);
  const randomVal = 11n;
  const randomBase8 = babyjubScalarMul(BABYJUB_BASE8, randomVal);
  const randomCoordPubKey = babyjubScalarMul(coordPubKey, randomVal);
  const d1 = babyjubAdd(randomBase8, c1);
  const d2 = babyjubAdd(randomCoordPubKey, c2);
  const sharedKey = babyjubScalarMul(coordPubKey, oldPrivateKey);
  const sharedKeyHash = hashLeftRight(sharedKey[0], sharedKey[1]);
  const deactivateLeaf = hash5([...c1, ...c2, sharedKeyHash]);
  const deactivateIndex = 42;
  const leaves = Array.from({ length: TREE_ARITY ** 4 }, () => 0n);
  leaves[deactivateIndex] = deactivateLeaf;
  const deactivateTree = pathFor(leaves, 4, deactivateIndex);
  const nullifier = hashLeftRight(oldPrivateKey, pollId);
  const newPubKey = babyjubScalarMul(BABYJUB_BASE8, 13n);
  const coordPubKeyHash = hashLeftRight(coordPubKey[0], coordPubKey[1]);
  const newPubKeyHash = hashLeftRight(newPubKey[0], newPubKey[1]);
  const inputHash = addNewKeyInputHash(
    deactivateTree.root,
    coordPubKeyHash,
    nullifier,
    d1[0],
    d1[1],
    d2[0],
    d2[1],
    newPubKeyHash,
    pollId,
  );

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

test('validates AMACI AddNewKey compatibility relation', () => {
  const input = buildFixture();
  const result = evaluateAddNewKey(input);

  assert.equal(result.derived.deactivateLeaf.toString(), input.deactivateLeaf);
  assert.equal(result.derived.deactivateRoot.toString(), input.deactivateRoot);
  assert.equal(result.derived.inputHash.toString(), input.inputHash);
  assert.equal(result.publicOutput.felts.length, 25);
});

test('builds Cairo executable arguments for AddNewKey', () => {
  const input = buildFixture();
  const evaluated = evaluateAddNewKey(input);
  const cairoInput = buildCairoAddNewKeyInput(input, evaluated);
  const args = serializeCairoAddNewKeyExecutableArgs(cairoInput);

  assert.equal(args.length, 10793);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.deepEqual(cairoInput.public_output, evaluated.publicOutput.decimalFelts);
});

test('builds native public hash arguments for AddNewKey', () => {
  const input = buildFixture();
  const evaluated = evaluateAddNewKey(input);
  const cairoInput = buildNativeCairoAddNewKeyInput(input, evaluated);
  const legacyInput = buildCairoAddNewKeyInput(input, evaluated);
  const args = serializeNativeCairoAddNewKeyExecutableArgs(cairoInput);
  const expectedNativeNullifier = poseidonManyFelts([
    ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN,
    toStarkFelt(evaluated.input.oldPrivateKey),
    toStarkFelt(evaluated.input.pollId),
  ]);

  assert.equal(cairoInput.public_output.length, 14);
  assert.ok(cairoInput.public_output_labels.includes('hash_scheme'));
  assert.equal(cairoInput.publicFields.deactivate_root_hash, toStarkFelt(evaluated.input.deactivateRoot));
  assert.equal(cairoInput.publicFields.poll_id, evaluated.input.pollId);
  assert.equal(cairoInput.publicFields.nullifier, expectedNativeNullifier);
  assert.notEqual(cairoInput.publicFields.coord_pub_key_hash, evaluated.publicFields.coordPubKeyHash);
  assert.notEqual(cairoInput.publicFields.new_pub_key_hash, evaluated.publicFields.newPubKeyHash);
  assert.notEqual(cairoInput.publicFields.input_hash, evaluated.publicFields.inputHash);
  assert.deepEqual(cairoInput.program_input.witness.legacy, legacyInput.program_input.witness);
  assert.ok(args.length > legacyInput.public_output.length);
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
