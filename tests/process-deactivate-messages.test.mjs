import { test } from 'node:test';
import assert from 'node:assert/strict';
import { joinU128Pair } from '../src/compat/encoding.mjs';
import { hash5, hash10, hashLeftRight } from '../src/compat/poseidon.mjs';
import { processDeactivateInputHash } from '../src/compat/encoding.mjs';
import { BABYJUB_BASE8, babyjubScalarMul, poseidonSignatureMessage } from '../src/compat/babyjub.mjs';
import { packCommandData, poseidonEncryptWithoutCheck7 } from '../src/msg/process-one.mjs';
import {
  buildCairoProcessDeactivateMessagesBoundaryInput,
  buildCairoProcessDeactivateMessageStepInput,
  buildCairoProcessDeactivateMessagesStateTransitionInput,
  buildCairoProcessDeactivateMessagesStatefulInput,
  serializeCairoProcessDeactivateMessagesBoundaryExecutableArgs,
  serializeCairoProcessDeactivateMessageStepExecutableArgs,
  serializeCairoProcessDeactivateMessagesStateTransitionExecutableArgs,
  serializeCairoProcessDeactivateMessagesStatefulExecutableArgs,
} from '../src/deactivate/cairo-input.mjs';
import {
  evaluateProcessDeactivateMessages,
  evaluateProcessDeactivateMessagesStateTransition,
  evaluateProcessDeactivateMessagesStateful,
  processDeactivateMessageHash,
  processDeactivateMessageHashChain,
} from '../src/deactivate/process-deactivate-messages.mjs';
import {
  elGamalDecryptPoint,
  evaluateProcessDeactivateOne,
} from '../src/deactivate/process-deactivate-one.mjs';
import { requireZkKitPackage } from '../src/compat/zk-kit-require.mjs';

const { derivePublicKey, signMessage } = requireZkKitPackage('@zk-kit/eddsa-poseidon');

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
  const coordPubKey = [11n, 12n];
  const currentActiveStateRoot = 101n;
  const currentDeactivateRoot = 202n;
  const currentDeactivateCommitment = hashLeftRight(currentActiveStateRoot, currentDeactivateRoot);
  const newDeactivateRoot = 303n;
  const newDeactivateCommitment = hashLeftRight(404n, newDeactivateRoot);
  const currentStateRoot = 505n;
  const expectedPollId = 77n;
  const batchStartHash = 123n;
  const msgs = [
    [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n],
    [0n, 99n, 98n, 97n, 96n, 95n, 94n, 93n, 92n, 91n],
    [11n, 12n, 13n, 14n, 15n, 16n, 17n, 18n, 19n, 20n],
    [0n, 88n, 87n, 86n, 85n, 84n, 83n, 82n, 81n, 80n],
    [21n, 22n, 23n, 24n, 25n, 26n, 27n, 28n, 29n, 30n],
  ];
  const encPubKeys = [
    [31n, 32n],
    [33n, 34n],
    [35n, 36n],
    [37n, 38n],
    [39n, 40n],
  ];
  const { endHash } = processDeactivateMessageHashChain(msgs, encPubKeys, batchStartHash);
  const coordPubKeyHash = hashLeftRight(coordPubKey[0], coordPubKey[1]);
  const inputHash = processDeactivateInputHash(
    newDeactivateRoot,
    coordPubKeyHash,
    batchStartHash,
    endHash,
    currentDeactivateCommitment,
    newDeactivateCommitment,
    currentStateRoot,
    expectedPollId,
  );

  return decimalize({
    inputHash,
    newDeactivateRoot,
    coordPubKey,
    batchStartHash,
    batchEndHash: endHash,
    currentActiveStateRoot,
    currentDeactivateRoot,
    currentDeactivateCommitment,
    newDeactivateCommitment,
    currentStateRoot,
    expectedPollId,
    msgs,
    encPubKeys,
  });
}

function quinaryLayers(leaves, depth) {
  let level = leaves.map(BigInt);
  const layers = [level];
  for (let d = 0; d < depth; d += 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 5) {
      next.push(hash5(level.slice(i, i + 5)));
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
    const idx = cursor % 5;
    const groupStart = cursor - idx;
    const siblings = [];
    for (let i = 0; i < 5; i += 1) {
      if (i !== idx) {
        siblings.push(layers[level][groupStart + i]);
      }
    }
    path.push(siblings);
    cursor = Math.floor(cursor / 5);
  }
  return {
    root: layers[depth][0],
    path,
  };
}

function identityDecryptCiphertext(coordPrivKey, randomScalar) {
  const c1 = babyjubScalarMul(BABYJUB_BASE8, randomScalar);
  const c2 = babyjubScalarMul(c1, coordPrivKey);
  const decrypt = elGamalDecryptPoint(c1, c2, coordPrivKey);
  assert.equal(decrypt.decryptedPoint[0], 0n);
  assert.equal(decrypt.isOdd, 0n);
  return { c1, c2 };
}

function buildStatefulFixture() {
  const coordPrivKey = 5n;
  const coordPubKey = babyjubScalarMul(BABYJUB_BASE8, coordPrivKey);
  const expectedPollId = 77n;
  const deactivateIndex0 = 40n;
  const emptyStateLeafHash = hash10([0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
  const stateLeafHashes = Array.from({ length: 25 }, () => emptyStateLeafHash);
  const stateLeaves = [];

  for (let i = 0; i < 5; i += 1) {
    const secretKey = Buffer.from([21 + i, 34 + i, 55 + i, 89 + i, 144 + i]);
    const statePubKey = derivePublicKey(secretKey).map(BigInt);
    const currentCiphertext = identityDecryptCiphertext(coordPrivKey, BigInt(20 + i));
    const stateLeaf = [
      ...statePubKey,
      100n + BigInt(i),
      0n,
      5n,
      currentCiphertext.c1[0],
      currentCiphertext.c1[1],
      currentCiphertext.c2[0],
      currentCiphertext.c2[1],
      0n,
    ];
    stateLeaves.push({ secretKey, stateLeaf });
    stateLeafHashes[i] = hash10(stateLeaf);
  }

  const stateTree = pathFor(stateLeafHashes, 2, 0);
  const currentStateRoot = stateTree.root;
  const activeLeaves = Array.from({ length: 25 }, () => 0n);
  const deactivateLeaves = Array.from({ length: 625 }, () => 0n);
  const currentActiveStateRoot = pathFor(activeLeaves, 2, 0).root;
  const currentDeactivateRoot = pathFor(deactivateLeaves, 4, 0).root;
  const processOneWitnesses = [];
  const msgs = [];
  const encPubKeys = [];

  let activeRoot = currentActiveStateRoot;
  let deactivateRoot = currentDeactivateRoot;
  for (let i = 0; i < 5; i += 1) {
    const stateIndex = i;
    const deactivateIndex = Number(deactivateIndex0) + i;
    const { secretKey, stateLeaf } = stateLeaves[i];
    const statePath = pathFor(stateLeafHashes, 2, stateIndex);
    const activePath = pathFor(activeLeaves, 2, stateIndex);
    const deactivatePath = pathFor(deactivateLeaves, 4, deactivateIndex);
    const newCiphertext = identityDecryptCiphertext(coordPrivKey, BigInt(30 + i));
    const packedCmd = [
      packCommandData({
        pollId: expectedPollId,
        newVoteWeight: 0n,
        voteOptionIndex: 0n,
        stateIndex: BigInt(stateIndex),
        nonce: 0n,
      }),
      0n,
      0n,
    ];
    const signature = signMessage(secretKey, poseidonSignatureMessage(packedCmd));
    const encPubKey = babyjubScalarMul(BABYJUB_BASE8, BigInt(70 + i));
    const sharedKey = babyjubScalarMul(encPubKey, coordPrivKey);
    const decryptedCommand = [
      packedCmd[0],
      packedCmd[1],
      packedCmd[2],
      900n + BigInt(i),
      signature.R8.map(BigInt)[0],
      signature.R8.map(BigInt)[1],
      BigInt(signature.S),
    ];
    const msg = poseidonEncryptWithoutCheck7(decryptedCommand, sharedKey);
    const processOne = {
      isEmptyMsg: 0n,
      coordPrivKey,
      currentStateRoot,
      c1: newCiphertext.c1,
      c2: newCiphertext.c2,
      currentActiveStateRoot: activeRoot,
      currentDeactivateRoot: deactivateRoot,
      stateLeaf,
      stateLeafPathElements: statePath.path,
      activeStateLeafPathElements: activePath.path,
      currentActiveState: activeLeaves[stateIndex],
      newActiveState: BigInt(i + 1),
      cmdStateIndex: BigInt(stateIndex),
      cmdPollId: expectedPollId,
      cmdSigR8: signature.R8.map(BigInt),
      cmdSigS: BigInt(signature.S),
      packedCmd,
      expectedPollId,
      deactivateIndex: BigInt(deactivateIndex),
      deactivateLeafPathElements: deactivatePath.path,
    };
    const evaluated = evaluateProcessDeactivateOne(decimalize(processOne));
    activeLeaves[stateIndex] = processOne.newActiveState;
    deactivateLeaves[deactivateIndex] = evaluated.derived.deactivateLeaf;
    activeRoot = evaluated.derived.newActiveStateRoot;
    deactivateRoot = evaluated.derived.newDeactivateRoot;
    msgs.push(msg);
    encPubKeys.push(encPubKey);
    processOneWitnesses.push({
      ...processOne,
      newActiveStateRoot: activeRoot,
      newDeactivateRoot: deactivateRoot,
    });
  }

  const batchStartHash = 123n;
  const { endHash } = processDeactivateMessageHashChain(msgs, encPubKeys, batchStartHash);
  const currentDeactivateCommitment = hashLeftRight(currentActiveStateRoot, currentDeactivateRoot);
  const newDeactivateCommitment = hashLeftRight(activeRoot, deactivateRoot);
  const coordPubKeyHash = hashLeftRight(coordPubKey[0], coordPubKey[1]);
  const inputHash = processDeactivateInputHash(
    deactivateRoot,
    coordPubKeyHash,
    batchStartHash,
    endHash,
    currentDeactivateCommitment,
    newDeactivateCommitment,
    currentStateRoot,
    expectedPollId,
  );

  return decimalize({
    inputHash,
    newDeactivateRoot: deactivateRoot,
    coordPubKey,
    batchStartHash,
    batchEndHash: endHash,
    currentActiveStateRoot,
    currentDeactivateRoot,
    currentDeactivateCommitment,
    newDeactivateCommitment,
    currentStateRoot,
    expectedPollId,
    msgs,
    encPubKeys,
    coordPrivKey,
    deactivateIndex0,
    newActiveStateRoot: activeRoot,
    processOneWitnesses,
  });
}

let cachedStatefulFixture;

function getStatefulFixture() {
  cachedStatefulFixture ??= buildStatefulFixture();
  return JSON.parse(JSON.stringify(cachedStatefulFixture));
}

function recomputeProcessDeactivateBoundary(input) {
  const msgs = input.msgs.map((row) => row.map(BigInt));
  const encPubKeys = input.encPubKeys.map((row) => row.map(BigInt));
  const { endHash } = processDeactivateMessageHashChain(
    msgs,
    encPubKeys,
    BigInt(input.batchStartHash),
  );
  const coordPubKeyHash = hashLeftRight(BigInt(input.coordPubKey[0]), BigInt(input.coordPubKey[1]));
  input.batchEndHash = endHash.toString();
  input.inputHash = processDeactivateInputHash(
    BigInt(input.newDeactivateRoot),
    coordPubKeyHash,
    BigInt(input.batchStartHash),
    endHash,
    BigInt(input.currentDeactivateCommitment),
    BigInt(input.newDeactivateCommitment),
    BigInt(input.currentStateRoot),
    BigInt(input.expectedPollId),
  ).toString();
}

test('validates AMACI ProcessDeactivateMessages public boundary', () => {
  const input = buildFixture();
  const result = evaluateProcessDeactivateMessages(input);

  assert.equal(result.derived.messageHashChain.length, 6);
  assert.equal(result.derived.messageHashChain[1], processDeactivateMessageHash(input.msgs[0], input.encPubKeys[0], input.batchStartHash));
  assert.equal(result.derived.messageHashChain[2], result.derived.messageHashChain[1]);
  assert.equal(result.derived.messageHashChain[4], result.derived.messageHashChain[3]);
  assert.equal(result.derived.inputHash.toString(), input.inputHash);
  assert.equal(result.publicOutput.decimalFelts.length, 24);
});

test('builds Cairo executable arguments for ProcessDeactivateMessages boundary', () => {
  const input = buildFixture();
  const evaluated = evaluateProcessDeactivateMessages(input);
  const cairoInput = buildCairoProcessDeactivateMessagesBoundaryInput(input, evaluated);
  const args = serializeCairoProcessDeactivateMessagesBoundaryExecutableArgs(cairoInput);

  assert.equal(args.length, 364);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.equal(
    joinU128Pair(
      cairoInput.fields.input_hash.low,
      cairoInput.fields.input_hash.high,
    ).toString(),
    evaluated.derived.inputHash.toString(),
  );
});

test('chains five AMACI ProcessDeactivate ProcessOne witnesses', () => {
  const input = getStatefulFixture();
  const result = evaluateProcessDeactivateMessagesStateTransition(input);

  assert.equal(result.transitions.length, 5);
  assert.equal(result.derived.newActiveStateRoot.toString(), input.newActiveStateRoot);
  assert.equal(result.derived.newDeactivateRoot.toString(), input.newDeactivateRoot);
});

test('validates stateful AMACI ProcessDeactivateMessages relation', () => {
  const input = getStatefulFixture();
  const result = evaluateProcessDeactivateMessagesStateful(input);

  assert.equal(result.derived.newDeactivateRoot.toString(), input.newDeactivateRoot);
  assert.equal(result.derived.newDeactivateCommitment.toString(), input.newDeactivateCommitment);
  assert.equal(result.publicOutput.decimalFelts.length, 24);
});

test('builds Cairo executable arguments for ProcessDeactivateMessages state transition', () => {
  const input = getStatefulFixture();
  const evaluated = evaluateProcessDeactivateMessagesStateTransition(input);
  const cairoInput = buildCairoProcessDeactivateMessagesStateTransitionInput(input, evaluated);
  const args = serializeCairoProcessDeactivateMessagesStateTransitionExecutableArgs(cairoInput);

  assert.ok(args.length > 89000);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.equal(
    joinU128Pair(
      cairoInput.expected_output.new_deactivate_root.low,
      cairoInput.expected_output.new_deactivate_root.high,
    ).toString(),
    evaluated.derived.newDeactivateRoot.toString(),
  );
});

test('builds Cairo executable arguments for stateful ProcessDeactivateMessages', () => {
  const input = getStatefulFixture();
  const evaluated = evaluateProcessDeactivateMessagesStateful(input);
  const cairoInput = buildCairoProcessDeactivateMessagesStatefulInput(input, evaluated);
  const args = serializeCairoProcessDeactivateMessagesStatefulExecutableArgs(cairoInput);

  assert.ok(args.length > 91000);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.deepEqual(cairoInput.public_output, evaluated.publicOutput.decimalFelts);
});

test('builds Cairo executable arguments for linked ProcessDeactivateMessages step proof', () => {
  const input = getStatefulFixture();
  const evaluated = evaluateProcessDeactivateMessagesStateful(input);
  const cairoInput = buildCairoProcessDeactivateMessageStepInput(input, 2, evaluated);
  const args = serializeCairoProcessDeactivateMessageStepExecutableArgs(cairoInput);
  const transition = evaluated.state.transitions[2];

  assert.equal(cairoInput.public_output.length, 31);
  assert.equal(cairoInput.publicFields.messageIndex, 2n);
  assert.equal(cairoInput.publicFields.previousMessageHash, evaluated.boundary.derived.messageHashChain[2]);
  assert.equal(cairoInput.publicFields.nextMessageHash, evaluated.boundary.derived.messageHashChain[3]);
  assert.equal(cairoInput.publicFields.currentActiveStateRoot, transition.input.currentActiveStateRoot);
  assert.equal(cairoInput.publicFields.currentDeactivateRoot, transition.input.currentDeactivateRoot);
  assert.equal(cairoInput.publicFields.newActiveStateRoot, transition.derived.newActiveStateRoot);
  assert.equal(cairoInput.publicFields.newDeactivateRoot, transition.derived.newDeactivateRoot);
  assert.ok(args.length > 22000);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
});

test('rejects tampered ProcessDeactivateMessages batch end hash', () => {
  const input = buildFixture();
  input.batchEndHash = '1';

  assert.throws(() => evaluateProcessDeactivateMessages(input), /inputHash mismatch|batchEndHash mismatch/);
});

test('rejects a broken ProcessDeactivateMessages root chain', () => {
  const input = getStatefulFixture();
  input.processOneWitnesses[2].currentDeactivateRoot = '1';

  assert.throws(
    () => evaluateProcessDeactivateMessagesStateTransition(input),
    /currentDeactivateRoot mismatch/,
  );
});

test('rejects stateful ProcessDeactivateMessages with inconsistent final commitment', () => {
  const input = getStatefulFixture();
  input.newDeactivateCommitment = '1';

  assert.throws(
    () => evaluateProcessDeactivateMessagesStateful(input),
    /newDeactivateCommitment mismatch|inputHash mismatch/,
  );
});

test('rejects tampered ProcessDeactivateMessages current deactivate commitment', () => {
  const input = buildFixture();
  input.currentDeactivateCommitment = '1';

  assert.throws(() => evaluateProcessDeactivateMessages(input), /currentDeactivateCommitment mismatch/);
});

test('rejects ProcessDeactivateMessages when boundary message no longer decrypts to ProcessOne command', () => {
  const input = getStatefulFixture();
  input.msgs[0][0] = (BigInt(input.msgs[0][0]) + 1n).toString();
  recomputeProcessDeactivateBoundary(input);

  assert.throws(
    () => evaluateProcessDeactivateMessagesStateful(input),
    /packedCmd\[0\] mismatch|cmdPollId mismatch|cmdStateIndex mismatch/,
  );
});

test('rejects an empty deactivate boundary slot driving a non-empty ProcessOne witness', () => {
  const input = getStatefulFixture();
  input.msgs[0][0] = '0';
  recomputeProcessDeactivateBoundary(input);

  assert.throws(
    () => evaluateProcessDeactivateMessagesStateful(input),
    /processOneWitnesses\[0\]\.isEmptyMsg mismatch/,
  );
});

test('rejects ProcessDeactivateMessages witness with zero new active state', () => {
  const input = getStatefulFixture();
  input.processOneWitnesses[0].newActiveState = '0';

  assert.throws(
    () => evaluateProcessDeactivateMessagesStateful(input),
    /newActiveState must be non-zero/,
  );
});
