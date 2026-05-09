import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TREE_ARITY } from '../src/constants.mjs';
import { joinU128Pair } from '../src/compat/encoding.mjs';
import { hash5, hash10 } from '../src/compat/poseidon.mjs';
import {
  buildCairoProcessOneStateTransitionInput,
  buildCairoProcessOneWithEcdhSignatureInput,
  buildCairoProcessOneWithEcdhInput,
  buildCairoProcessOneWithSignatureInput,
  serializeCairoProcessOneStateTransitionExecutableArgs,
  serializeCairoProcessOneWithEcdhSignatureExecutableArgs,
  serializeCairoProcessOneWithEcdhExecutableArgs,
  serializeCairoProcessOneWithSignatureExecutableArgs,
} from '../src/msg/cairo-input.mjs';
import {
  BABYJUB_BASE8,
  babyjubScalarMul,
  buildEcdhSharedKeyWitness,
  poseidonSignatureMessage,
} from '../src/compat/babyjub.mjs';
import {
  evaluateProcessOneStateTransition,
  packCommandData,
  poseidonEncryptWithoutCheck7,
} from '../src/msg/process-one.mjs';
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

function buildActiveCiphertext(coordPrivKey, seed) {
  const c1 = babyjubScalarMul(BABYJUB_BASE8, BigInt(seed));
  const c2 = babyjubScalarMul(c1, coordPrivKey);
  return { c1, c2 };
}

function buildFixture({
  isValid = true,
  sharedKey = [12345n, 67890n],
  signatureSecretKey,
  coordPrivKey = 5n,
} = {}) {
  const cmdStateIndex = 7;
  const cmdVoteOptionIndex = 3;
  const isQuadraticCost = 0n;
  const numSignUps = 15n;
  const maxVoteOptions = 5n;
  const expectedPollId = 77n;
  const stateIndex = isValid ? cmdStateIndex : 24;
  const voteOptionIndex = isValid ? cmdVoteOptionIndex : 0;
  const voteLeaves = [2n, 4n, 6n, 8n, 10n];
  const voteTree = pathFor(voteLeaves, 1, voteOptionIndex);
  const statePubKey = signatureSecretKey
    ? derivePublicKey(signatureSecretKey).map(BigInt)
    : [111n, 222n];
  const activeCiphertext = buildActiveCiphertext(coordPrivKey, 17n);
  const stateLeaf = [
    ...statePubKey,
    100n,
    voteTree.root,
    5n,
    ...activeCiphertext.c1,
    ...activeCiphertext.c2,
    9n,
  ];
  const emptyStateLeafHash = hash10([0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
  const stateLeafHashes = Array.from({ length: 25 }, () => emptyStateLeafHash);
  stateLeafHashes[stateIndex] = hash10(stateLeaf);
  const stateTree = pathFor(stateLeafHashes, 2, stateIndex);

  const activeLeaves = Array.from({ length: 25 }, () => 0n);
  const activeTree = pathFor(activeLeaves, 2, stateIndex);
  const currentVoteWeight = voteLeaves[voteOptionIndex];
  const cmdNewVoteWeight = 13n;
  const cmdNonce = stateLeaf[4] + 1n;
  const newBalance = stateLeaf[2] + currentVoteWeight - cmdNewVoteWeight;
  const cmdNewPubKey = [333n, 444n];
  const cmdSalt = 555n;
  const packedCommand = [
    packCommandData({
      pollId: expectedPollId,
      newVoteWeight: cmdNewVoteWeight,
      voteOptionIndex: BigInt(cmdVoteOptionIndex),
      stateIndex: BigInt(cmdStateIndex),
      nonce: cmdNonce,
    }),
    ...cmdNewPubKey,
  ];
  const signature = signatureSecretKey
    ? signMessage(signatureSecretKey, poseidonSignatureMessage(packedCommand))
    : { R8: [666n, 777n], S: 888n };
  const cmdSigR8 = signature.R8.map(BigInt);
  const cmdSigS = BigInt(signature.S);
  const decryptedCommand = [packedCommand[0], ...cmdNewPubKey, cmdSalt, ...cmdSigR8, cmdSigS];
  const msg = poseidonEncryptWithoutCheck7(decryptedCommand, sharedKey);

  const base = {
    isQuadraticCost,
    coordPrivKey,
    numSignUps,
    maxVoteOptions,
    expectedPollId,
    isSignatureValid: isValid ? 1n : 0n,
    isDecryptionActive: 1n,
    msg,
    sharedKey,
    decryptedCommand,
    packedCommand,
    cmdSalt,
    cmdSigR8,
    cmdSigS,
    currentStateRoot: stateTree.root,
    activeStateRoot: activeTree.root,
    stateLeaf,
    stateLeafPathElements: stateTree.path,
    activeStateLeaf: activeLeaves[stateIndex],
    activeStateLeafPathElements: activeTree.path,
    currentVoteWeight,
    currentVoteWeightsPathElements: voteTree.path,
    isValid: isValid ? 1n : 0n,
    cmdStateIndex: BigInt(cmdStateIndex),
    cmdVoteOptionIndex: BigInt(cmdVoteOptionIndex),
    cmdNewVoteWeight,
    cmdNonce,
    cmdPollId: expectedPollId,
    cmdNewPubKey,
    newBalance,
    newSlNonce: cmdNonce,
  };
  const result = evaluateProcessOneStateTransition(decimalize(base));
  return decimalize({
    ...base,
    newStateRoot: result.derived.newStateRoot,
  });
}

test('validates ProcessOne state inclusion and vote root update skeleton', () => {
  const input = buildFixture();
  const result = evaluateProcessOneStateTransition(input);

  assert.equal(result.derived.stateIndex, 7n);
  assert.equal(result.derived.voteOptionIndex, 3n);
  assert.equal(result.derived.updatedVoteWeight, 13n);
  assert.equal(result.derived.newStateRoot.toString(), input.newStateRoot);
  assert.deepEqual(
    result.derived.newStateLeaf.slice(0, 5).map((value) => value.toString()),
    ['333', '444', '95', result.derived.newVoteOptionRoot.toString(), '6'],
  );
});

test('applies ProcessOne invalid-message selectors', () => {
  const input = buildFixture({ isValid: false });
  const result = evaluateProcessOneStateTransition(input);

  assert.equal(result.derived.stateIndex, 24n);
  assert.equal(result.derived.voteOptionIndex, 0n);
  assert.equal(result.derived.updatedVoteWeight.toString(), input.currentVoteWeight);
  assert.equal(result.derived.newStateRoot.toString(), input.newStateRoot);
  assert.deepEqual(
    result.derived.newStateLeaf.map((value) => value.toString()),
    [
      '111',
      '222',
      '100',
      result.derived.newVoteOptionRoot.toString(),
      '5',
      ...input.stateLeaf.slice(5, 9),
      '0',
    ],
  );
});

test('builds Cairo executable arguments for ProcessOne state transition', () => {
  const input = buildFixture();
  const evaluated = evaluateProcessOneStateTransition(input);
  const cairoInput = buildCairoProcessOneStateTransitionInput(input, evaluated);
  const args = serializeCairoProcessOneStateTransitionExecutableArgs(cairoInput);

  assert.equal(args.length, 152);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.equal(
    joinU128Pair(
      cairoInput.expected_output.new_state_root.low,
      cairoInput.expected_output.new_state_root.high,
    ).toString(),
    evaluated.derived.newStateRoot.toString(),
  );
});

test('builds Cairo executable arguments for ProcessOne with ECDH shared-key binding', () => {
  const ecdh = buildEcdhSharedKeyWitness(5n, BABYJUB_BASE8);
  const input = buildFixture({ sharedKey: ecdh.expected });
  const evaluated = evaluateProcessOneStateTransition(input);
  const cairoInput = buildCairoProcessOneWithEcdhInput(input, ecdh, evaluated);
  const args = serializeCairoProcessOneWithEcdhExecutableArgs(cairoInput);

  assert.equal(args.length, 3705);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.equal(
    joinU128Pair(
      cairoInput.expected_output.new_state_root.low,
      cairoInput.expected_output.new_state_root.high,
    ).toString(),
    evaluated.derived.newStateRoot.toString(),
  );
});

test('builds Cairo executable arguments for ProcessOne with signature binding', () => {
  const input = buildFixture({ signatureSecretKey: Buffer.from([1, 2, 3, 4, 5]) });
  const evaluated = evaluateProcessOneStateTransition(input);
  const cairoInput = buildCairoProcessOneWithSignatureInput(input, evaluated);
  const args = serializeCairoProcessOneWithSignatureExecutableArgs(cairoInput);

  assert.equal(args.length, 7288);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.equal(
    joinU128Pair(
      cairoInput.expected_output.new_state_root.low,
      cairoInput.expected_output.new_state_root.high,
    ).toString(),
    evaluated.derived.newStateRoot.toString(),
  );
});

test('builds Cairo executable arguments for ProcessOne with ECDH and signature binding', () => {
  const ecdh = buildEcdhSharedKeyWitness(5n, BABYJUB_BASE8);
  const input = buildFixture({
    sharedKey: ecdh.expected,
    signatureSecretKey: Buffer.from([9, 8, 7, 6, 5]),
  });
  const evaluated = evaluateProcessOneStateTransition(input);
  const cairoInput = buildCairoProcessOneWithEcdhSignatureInput(input, ecdh, evaluated);
  const args = serializeCairoProcessOneWithEcdhSignatureExecutableArgs(cairoInput);

  assert.equal(args.length, 10841);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.equal(
    joinU128Pair(
      cairoInput.expected_output.new_state_root.low,
      cairoInput.expected_output.new_state_root.high,
    ).toString(),
    evaluated.derived.newStateRoot.toString(),
  );
});

test('rejects ProcessOne signature input which does not match isSignatureValid', () => {
  const input = buildFixture({
    isValid: false,
    signatureSecretKey: Buffer.from([1, 1, 2, 3, 5]),
  });

  assert.throws(
    () => buildCairoProcessOneWithSignatureInput(input),
    /signature verification result does not match ProcessOne isSignatureValid/,
  );
});

test('rejects ProcessOne ECDH input which does not match the shared-key witness', () => {
  const input = buildFixture();
  const ecdh = buildEcdhSharedKeyWitness(5n, BABYJUB_BASE8);

  assert.throws(
    () => buildCairoProcessOneWithEcdhInput(input, ecdh),
    /ECDH shared key does not match ProcessOne sharedKey witness/,
  );
});

test('rejects a tampered ProcessOne vote weight witness', () => {
  const input = buildFixture();
  input.currentVoteWeight = '9';
  input.newBalance = '96';

  assert.throws(() => evaluateProcessOneStateTransition(input), /currentVoteRoot mismatch/);
});

test('rejects a tampered ProcessOne state root', () => {
  const input = buildFixture();
  input.currentStateRoot = '1';

  assert.throws(() => evaluateProcessOneStateTransition(input), /currentStateRoot mismatch/);
});

test('rejects a tampered valid ProcessOne balance witness', () => {
  const input = buildFixture();
  input.newBalance = '1';

  assert.throws(() => evaluateProcessOneStateTransition(input), /newBalance mismatch/);
});

test('rejects a ProcessOne command for the wrong poll id', () => {
  const input = buildFixture();
  input.cmdPollId = '78';

  assert.throws(() => evaluateProcessOneStateTransition(input), /cmdPollId mismatch/);
});

test('rejects a ProcessOne command whose packed data does not match command fields', () => {
  const input = buildFixture();
  input.packedCommand[0] = '1';

  assert.throws(() => evaluateProcessOneStateTransition(input), /packedCommand\[0\] mismatch/);
});

test('rejects a ProcessOne decrypted command whose signature fields drift', () => {
  const input = buildFixture();
  input.cmdSigR8[0] = '1';

  assert.throws(() => evaluateProcessOneStateTransition(input), /cmdSigR8\[0\] mismatch/);
});

test('rejects a ProcessOne message which does not decrypt to the command', () => {
  const input = buildFixture();
  input.msg[0] = '1';

  assert.throws(() => evaluateProcessOneStateTransition(input), /decryptedCommand\[0\] mismatch/);
});
