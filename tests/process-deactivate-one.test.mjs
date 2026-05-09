import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TREE_ARITY } from '../src/constants.mjs';
import { joinU128Pair } from '../src/compat/encoding.mjs';
import { hash5, hash10 } from '../src/compat/poseidon.mjs';
import { BABYJUB_BASE8, babyjubScalarMul, poseidonSignatureMessage } from '../src/compat/babyjub.mjs';
import { packCommandData } from '../src/msg/process-one.mjs';
import {
  buildCairoProcessDeactivateOneInput,
  serializeCairoProcessDeactivateOneExecutableArgs,
} from '../src/deactivate/cairo-input.mjs';
import {
  elGamalDecryptPoint,
  evaluateProcessDeactivateOne,
} from '../src/deactivate/process-deactivate-one.mjs';
import { requireZkKitPackage } from '../src/compat/zk-kit-require.mjs';

const { derivePublicKey, signMessage } = requireZkKitPackage('@zk-kit/eddsa-poseidon');

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

function identityDecryptCiphertext(coordPrivKey, randomScalar) {
  const c1 = babyjubScalarMul(BABYJUB_BASE8, randomScalar);
  const c2 = babyjubScalarMul(c1, coordPrivKey);
  const decrypt = elGamalDecryptPoint(c1, c2, coordPrivKey);
  assert.equal(decrypt.decryptedPoint[0], 0n);
  assert.equal(decrypt.isOdd, 0n);
  return { c1, c2 };
}

function buildFixture() {
  const coordPrivKey = 5n;
  const stateSecretKey = Buffer.from([21, 34, 55, 89, 144]);
  const statePubKey = derivePublicKey(stateSecretKey).map(BigInt);
  const stateIndex = 7;
  const deactivateIndex = 42;
  const pollId = 77n;
  const currentCiphertext = identityDecryptCiphertext(coordPrivKey, 2n);
  const newCiphertext = identityDecryptCiphertext(coordPrivKey, 3n);
  const stateLeaf = [
    ...statePubKey,
    100n,
    0n,
    5n,
    currentCiphertext.c1[0],
    currentCiphertext.c1[1],
    currentCiphertext.c2[0],
    currentCiphertext.c2[1],
    0n,
  ];
  const emptyStateLeafHash = hash10([0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
  const stateLeafHashes = Array.from({ length: 25 }, () => emptyStateLeafHash);
  stateLeafHashes[stateIndex] = hash10(stateLeaf);
  const stateTree = pathFor(stateLeafHashes, 2, stateIndex);

  const activeLeaves = Array.from({ length: 25 }, () => 0n);
  const activeTree = pathFor(activeLeaves, 2, stateIndex);
  const deactivateLeaves = Array.from({ length: 625 }, () => 0n);
  const deactivateTree = pathFor(deactivateLeaves, 4, deactivateIndex);
  const newActiveState = 1n;
  const packedCmd = [
    packCommandData({
      pollId,
      newVoteWeight: 0n,
      voteOptionIndex: 0n,
      stateIndex: BigInt(stateIndex),
      nonce: 0n,
    }),
    0n,
    0n,
  ];
  const signature = signMessage(stateSecretKey, poseidonSignatureMessage(packedCmd));
  const base = {
    isEmptyMsg: 0n,
    coordPrivKey,
    currentStateRoot: stateTree.root,
    c1: newCiphertext.c1,
    c2: newCiphertext.c2,
    currentActiveStateRoot: activeTree.root,
    currentDeactivateRoot: deactivateTree.root,
    stateLeaf,
    stateLeafPathElements: stateTree.path,
    activeStateLeafPathElements: activeTree.path,
    currentActiveState: activeLeaves[stateIndex],
    newActiveState,
    cmdStateIndex: BigInt(stateIndex),
    cmdPollId: pollId,
    cmdSigR8: signature.R8.map(BigInt),
    cmdSigS: BigInt(signature.S),
    packedCmd,
    expectedPollId: pollId,
    deactivateIndex: BigInt(deactivateIndex),
    deactivateLeafPathElements: deactivateTree.path,
  };
  const result = evaluateProcessDeactivateOne(decimalize(base));
  return decimalize({
    ...base,
    newActiveStateRoot: result.derived.newActiveStateRoot,
    newDeactivateRoot: result.derived.newDeactivateRoot,
  });
}

test('validates AMACI ProcessDeactivate ProcessOne roots and decrypt parity', () => {
  const input = buildFixture();
  const result = evaluateProcessDeactivateOne(input);

  assert.equal(result.derived.signatureValid, 1n);
  assert.equal(result.derived.valid, 1n);
  assert.equal(result.derived.currentStateDecrypt.isOdd, 0n);
  assert.equal(result.derived.newStateDecrypt.isOdd, 0n);
  assert.equal(result.derived.stateIndex, 7n);
  assert.equal(result.derived.newActiveStateRoot.toString(), input.newActiveStateRoot);
  assert.equal(result.derived.newDeactivateRoot.toString(), input.newDeactivateRoot);
});

test('builds Cairo executable arguments for AMACI ProcessDeactivate ProcessOne', () => {
  const input = buildFixture();
  const evaluated = evaluateProcessDeactivateOne(input);
  const cairoInput = buildCairoProcessDeactivateOneInput(input, evaluated);
  const args = serializeCairoProcessDeactivateOneExecutableArgs(cairoInput);

  assert.ok(args.length > 17500);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.equal(
    joinU128Pair(
      cairoInput.expected_output.new_active_state_root.low,
      cairoInput.expected_output.new_active_state_root.high,
    ).toString(),
    evaluated.derived.newActiveStateRoot.toString(),
  );
  assert.equal(
    joinU128Pair(
      cairoInput.expected_output.new_deactivate_root.low,
      cairoInput.expected_output.new_deactivate_root.high,
    ).toString(),
    evaluated.derived.newDeactivateRoot.toString(),
  );
});

test('rejects tampered ProcessDeactivate active-state root', () => {
  const input = buildFixture();
  input.currentActiveStateRoot = '1';

  assert.throws(() => evaluateProcessDeactivateOne(input), /currentActiveStateRoot mismatch/);
});

test('rejects ProcessDeactivate witness with zero new active state', () => {
  const input = buildFixture();
  input.newActiveState = '0';

  assert.throws(() => evaluateProcessDeactivateOne(input), /newActiveState must be non-zero/);
});
