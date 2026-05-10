import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TREE_ARITY } from '../src/constants.mjs';
import { joinU128Pair, processMessagesInputHash } from '../src/compat/encoding.mjs';
import { hash5, hash10, hashLeftRight } from '../src/compat/poseidon.mjs';
import {
  buildCairoProcessMessageCoordKeyInput,
  buildCairoProcessMessageEcdhInput,
  buildCairoProcessMessageSignatureInput,
  buildCairoProcessMessageStepCoreInput,
  buildCairoProcessMessageStepWithEcdhSignatureInput,
  buildCairoProcessMessagesStateTransitionInput,
  buildCairoProcessMessagesStatefulWithEcdhSignatureInput,
  buildCairoProcessMessagesStatefulWithEcdhInput,
  buildCairoProcessMessagesStatefulInput,
  serializeCairoProcessMessageCoordKeyExecutableArgs,
  serializeCairoProcessMessageEcdhExecutableArgs,
  serializeCairoProcessMessageSignatureExecutableArgs,
  serializeCairoProcessMessageStepCoreExecutableArgs,
  serializeCairoProcessMessageStepWithEcdhSignatureExecutableArgs,
  serializeCairoProcessMessagesStateTransitionExecutableArgs,
  serializeCairoProcessMessagesStatefulWithEcdhSignatureExecutableArgs,
  serializeCairoProcessMessagesStatefulWithEcdhExecutableArgs,
  serializeCairoProcessMessagesStatefulExecutableArgs,
} from '../src/msg/cairo-input.mjs';
import {
  BABYJUB_BASE8,
  babyjubScalarMul,
  poseidonSignatureMessage,
} from '../src/compat/babyjub.mjs';
import {
  evaluateProcessMessagesStateful,
  evaluateProcessMessagesStateTransitions,
  packProcessMessagesVals,
  processMessageHashChain,
} from '../src/msg/process-messages.mjs';
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

function buildStateLeaf(
  seed,
  voteRoot,
  coordPrivKey,
  pubKey = [BigInt(seed * 100 + 1), BigInt(seed * 100 + 2)],
) {
  const activeCiphertext = buildActiveCiphertext(coordPrivKey, seed + 100);
  return [
    pubKey[0],
    pubKey[1],
    BigInt(seed * 100 + 3),
    voteRoot,
    BigInt(seed),
    ...activeCiphertext.c1,
    ...activeCiphertext.c2,
    BigInt(seed),
  ];
}

function processOneCost(isQuadraticCost, voteWeight) {
  return isQuadraticCost === 1n ? voteWeight * voteWeight : voteWeight;
}

function buildFixture({ sharedKeys, signatureSecretKeys } = {}) {
  const isQuadraticCost = 1n;
  const coordPrivKey = 5n;
  const numSignUps = 20n;
  const maxVoteOptions = 5n;
  const expectedPollId = 77n;
  const commands = [
    { isValid: true, stateIndex: 1, voteOptionIndex: 0, newVoteWeight: 31n },
    { isValid: true, stateIndex: 7, voteOptionIndex: 3, newVoteWeight: 37n },
    { isValid: false, stateIndex: 8, voteOptionIndex: 2, newVoteWeight: 41n },
    { isValid: true, stateIndex: 12, voteOptionIndex: 4, newVoteWeight: 43n },
    { isValid: true, stateIndex: 20, voteOptionIndex: 1, newVoteWeight: 47n },
  ];
  const emptyStateLeaf = Array.from({ length: 10 }, () => 0n);
  const voteLeavesByState = Array.from({ length: 25 }, (_, stateIndex) => [
    BigInt(stateIndex + 1),
    BigInt(stateIndex + 2),
    BigInt(stateIndex + 3),
    BigInt(stateIndex + 4),
    BigInt(stateIndex + 5),
  ]);
  const stateLeaves = Array.from({ length: 25 }, () => emptyStateLeaf.slice());
  const touchedStateIndexes = [1, 7, 12, 20, 24];
  const pubKeysByState = new Map();
  for (let i = 0; i < commands.length; i += 1) {
    if (commands[i].isValid && signatureSecretKeys?.[i]) {
      pubKeysByState.set(commands[i].stateIndex, derivePublicKey(signatureSecretKeys[i]).map(BigInt));
    }
  }
  for (const stateIndex of touchedStateIndexes) {
    const voteRoot = pathFor(voteLeavesByState[stateIndex], 1, 0).root;
    stateLeaves[stateIndex] = buildStateLeaf(
      stateIndex + 10,
      voteRoot,
      coordPrivKey,
      pubKeysByState.get(stateIndex),
    );
  }

  const activeLeaves = Array.from({ length: 25 }, () => 0n);
  const activeStateRoot = pathFor(activeLeaves, 2, 0).root;
  let stateLeafHashes = stateLeaves.map(hash10);
  const currentStateRoot = pathFor(stateLeafHashes, 2, 0).root;

  const processOneWitnesses = Array.from({ length: commands.length });
  for (let i = commands.length - 1; i >= 0; i -= 1) {
    const command = commands[i];
    const stateIndex = command.isValid ? command.stateIndex : 24;
    const voteOptionIndex = command.isValid ? command.voteOptionIndex : 0;
    const stateTree = pathFor(stateLeafHashes, 2, stateIndex);
    const activeTree = pathFor(activeLeaves, 2, stateIndex);
    const voteTree = pathFor(voteLeavesByState[stateIndex], 1, voteOptionIndex);
    const currentVoteWeight = voteLeavesByState[stateIndex][voteOptionIndex];
    const cmdNonce = stateLeaves[stateIndex][4] + 1n;
    const newBalance =
      stateLeaves[stateIndex][2] +
      processOneCost(isQuadraticCost, currentVoteWeight) -
      processOneCost(isQuadraticCost, command.newVoteWeight);
    const cmdNewPubKey = [BigInt(500 + i), BigInt(600 + i)];
    const cmdSalt = BigInt(700 + i);
    const sharedKey = sharedKeys?.[i] ?? [BigInt(1100 + i), BigInt(1200 + i)];
    const packedCommand = [
      packCommandData({
        pollId: expectedPollId,
        newVoteWeight: command.newVoteWeight,
        voteOptionIndex: BigInt(command.voteOptionIndex),
        stateIndex: BigInt(command.stateIndex),
        nonce: cmdNonce,
      }),
      ...cmdNewPubKey,
    ];
    const signature = signatureSecretKeys?.[i] && command.isValid
      ? signMessage(signatureSecretKeys[i], poseidonSignatureMessage(packedCommand))
      : { R8: [BigInt(800 + i), BigInt(900 + i)], S: BigInt(1000 + i) };
    const cmdSigR8 = signature.R8.map(BigInt);
    const cmdSigS = BigInt(signature.S);
    const decryptedCommand = [packedCommand[0], ...cmdNewPubKey, cmdSalt, ...cmdSigR8, cmdSigS];
    const msg = poseidonEncryptWithoutCheck7(decryptedCommand, sharedKey);
    const witness = {
      isQuadraticCost,
      coordPrivKey,
      numSignUps,
      maxVoteOptions,
      expectedPollId,
      isSignatureValid: command.isValid ? 1n : 0n,
      isDecryptionActive: 1n,
      msg,
      sharedKey,
      decryptedCommand,
      packedCommand,
      cmdSalt,
      cmdSigR8,
      cmdSigS,
      currentStateRoot: stateTree.root,
      activeStateRoot,
      stateLeaf: stateLeaves[stateIndex],
      stateLeafPathElements: stateTree.path,
      activeStateLeaf: activeLeaves[stateIndex],
      activeStateLeafPathElements: activeTree.path,
      currentVoteWeight,
      currentVoteWeightsPathElements: voteTree.path,
      isValid: command.isValid ? 1n : 0n,
      cmdStateIndex: BigInt(command.stateIndex),
      cmdVoteOptionIndex: BigInt(command.voteOptionIndex),
      cmdNewVoteWeight: command.newVoteWeight,
      cmdNonce,
      cmdPollId: expectedPollId,
      cmdNewPubKey,
      newBalance,
      newSlNonce: cmdNonce,
    };
    const evaluated = evaluateProcessOneStateTransition(decimalize(witness));
    processOneWitnesses[i] = witness;
    stateLeaves[stateIndex] = evaluated.derived.newStateLeaf;
    stateLeafHashes[stateIndex] = evaluated.derived.newStateLeafHash;
    if (command.isValid) {
      voteLeavesByState[stateIndex][voteOptionIndex] = command.newVoteWeight;
    }
  }

  const newStateRoot = pathFor(stateLeafHashes, 2, 0).root;
  return decimalize({
    currentStateRoot,
    coordPrivKey,
    activeStateRoot,
    newStateRoot,
    processOneWitnesses,
  });
}

function buildStatefulFixture({ state = buildFixture(), coordPrivKey, encPubKeys } = {}) {
  const effectiveCoordPrivKey = coordPrivKey ?? state.coordPrivKey;
  const packedVals = packProcessMessagesVals({
    isQuadraticCost: 1n,
    numSignUps: 20n,
    maxVoteOptions: 5n,
  });
  const coordPubKey =
    effectiveCoordPrivKey === undefined
      ? [11n, 22n]
      : babyjubScalarMul(BABYJUB_BASE8, BigInt(effectiveCoordPrivKey));
  const coordPubKeyHash = hashLeftRight(coordPubKey[0], coordPubKey[1]);
  const msgs = state.processOneWitnesses.map((witness) => witness.msg.map(BigInt));
  const messageEncPubKeys = encPubKeys ?? [
    [101n, 102n],
    [201n, 202n],
    [301n, 302n],
    [401n, 402n],
    [501n, 502n],
  ];
  const batchStartHash = 123n;
  const { endHash: batchEndHash } = processMessageHashChain(msgs, messageEncPubKeys, batchStartHash);
  const currentStateSalt = 701n;
  const newStateSalt = 702n;
  const deactivateRoot = 703n;
  const currentStateCommitment = hashLeftRight(state.currentStateRoot, currentStateSalt);
  const newStateCommitment = hashLeftRight(state.newStateRoot, newStateSalt);
  const deactivateCommitment = hashLeftRight(state.activeStateRoot, deactivateRoot);
  const expectedPollId = 77n;
  const inputHash = processMessagesInputHash(
    packedVals,
    coordPubKeyHash,
    batchStartHash,
    batchEndHash,
    currentStateCommitment,
    newStateCommitment,
    deactivateCommitment,
    expectedPollId,
  );

  return decimalize({
    ...state,
    packedVals,
    inputHash,
    coordPubKey,
    batchStartHash,
    batchEndHash,
    currentStateSalt,
    currentStateCommitment,
    newStateSalt,
    newStateCommitment,
    deactivateRoot,
    deactivateCommitment,
    expectedPollId,
    msgs,
    encPubKeys: messageEncPubKeys,
    ...(effectiveCoordPrivKey === undefined ? {} : { coordPrivKey: effectiveCoordPrivKey }),
  });
}

function buildStatefulEcdhFixture() {
  const coordPrivKey = 5n;
  const encPubKeys = [2n, 3n, 4n, 6n, 7n].map((scalar) =>
    babyjubScalarMul(BABYJUB_BASE8, scalar),
  );
  const sharedKeys = encPubKeys.map((pubKey) => babyjubScalarMul(pubKey, coordPrivKey));
  const state = buildFixture({ sharedKeys });
  return buildStatefulFixture({ state, coordPrivKey, encPubKeys });
}

function buildStatefulEcdhSignatureFixture() {
  const coordPrivKey = 5n;
  const encPubKeys = [2n, 3n, 4n, 6n, 7n].map((scalar) =>
    babyjubScalarMul(BABYJUB_BASE8, scalar),
  );
  const sharedKeys = encPubKeys.map((pubKey) => babyjubScalarMul(pubKey, coordPrivKey));
  const signatureSecretKeys = [
    Buffer.from([1, 2, 3, 4, 5]),
    Buffer.from([2, 3, 4, 5, 6]),
    undefined,
    Buffer.from([3, 4, 5, 6, 7]),
    Buffer.from([4, 5, 6, 7, 8]),
  ];
  const state = buildFixture({ sharedKeys, signatureSecretKeys });
  return buildStatefulFixture({ state, coordPrivKey, encPubKeys });
}

function ecdhInputsFor(input, coordPrivKey = input.coordPrivKey) {
  return input.encPubKeys.map((pubKey) => ({
    privKey: coordPrivKey.toString(),
    pubKey: pubKey.map((value) => value.toString()),
  }));
}

function recomputeProcessMessagesBoundary(input) {
  const msgs = input.msgs.map((row) => row.map(BigInt));
  const encPubKeys = input.encPubKeys.map((row) => row.map(BigInt));
  const { endHash } = processMessageHashChain(msgs, encPubKeys, BigInt(input.batchStartHash));
  input.batchEndHash = endHash.toString();
  input.inputHash = processMessagesInputHash(
    BigInt(input.packedVals),
    hashLeftRight(BigInt(input.coordPubKey[0]), BigInt(input.coordPubKey[1])),
    BigInt(input.batchStartHash),
    endHash,
    BigInt(input.currentStateCommitment),
    BigInt(input.newStateCommitment),
    BigInt(input.deactivateCommitment),
    BigInt(input.expectedPollId),
  ).toString();
}

test('chains five ProcessOne witnesses into a ProcessMessages state transition', () => {
  const input = buildFixture();
  const result = evaluateProcessMessagesStateTransitions(input);

  assert.equal(result.transitions.length, 5);
  assert.equal(result.derived.currentStateRoot.toString(), input.currentStateRoot);
  assert.equal(result.derived.newStateRoot.toString(), input.newStateRoot);
  assert.equal(result.transitions[2].derived.stateIndex, 24n);
  assert.equal(result.transitions[2].derived.voteOptionIndex, 0n);
});

test('rejects a broken ProcessMessages state-root chain', () => {
  const input = buildFixture();
  input.processOneWitnesses[2].currentStateRoot = '1';

  assert.throws(
    () => evaluateProcessMessagesStateTransitions(input),
    /processOneWitnesses\[2\]\.currentStateRoot mismatch|currentStateRoot mismatch/,
  );
});

test('builds Cairo executable arguments for ProcessMessages state transition', () => {
  const input = buildFixture();
  const evaluated = evaluateProcessMessagesStateTransitions(input);
  const cairoInput = buildCairoProcessMessagesStateTransitionInput(input, evaluated);
  const args = serializeCairoProcessMessagesStateTransitionExecutableArgs(cairoInput);

  assert.equal(args.length, 18553);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.equal(
    joinU128Pair(
      cairoInput.expected_output.new_state_root.low,
      cairoInput.expected_output.new_state_root.high,
    ).toString(),
    evaluated.derived.newStateRoot.toString(),
  );
});

test('builds Cairo executable arguments for stateful ProcessMessages skeleton', () => {
  const input = buildStatefulFixture();
  const evaluated = evaluateProcessMessagesStateful(input);
  const cairoInput = buildCairoProcessMessagesStatefulInput(input, evaluated);
  const args = serializeCairoProcessMessagesStatefulExecutableArgs(cairoInput);

  assert.equal(args.length, 18937);
  assert.equal(evaluated.publicOutput.felts.length, 24);
  assert.equal(evaluated.derived.stateTransitionNewStateRoot.toString(), input.newStateRoot);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
});

test('builds Cairo executable arguments for stateful ProcessMessages with ECDH binding', () => {
  const input = buildStatefulEcdhFixture();
  const evaluated = evaluateProcessMessagesStateful(input);
  const cairoInput = buildCairoProcessMessagesStatefulWithEcdhInput(input, evaluated);
  const args = serializeCairoProcessMessagesStatefulWithEcdhExecutableArgs(cairoInput);

  assert.equal(args.length, 40257);
  assert.equal(evaluated.publicOutput.felts.length, 24);
  assert.equal(evaluated.derived.stateTransitionNewStateRoot.toString(), input.newStateRoot);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
});

test('builds Cairo executable arguments for stateful ProcessMessages with ECDH and signature binding', () => {
  const input = buildStatefulEcdhSignatureFixture();
  const evaluated = evaluateProcessMessagesStateful(input);
  const cairoInput = buildCairoProcessMessagesStatefulWithEcdhSignatureInput(input, evaluated);
  const args = serializeCairoProcessMessagesStatefulWithEcdhSignatureExecutableArgs(cairoInput);

  assert.equal(args.length, 75937);
  assert.equal(evaluated.publicOutput.felts.length, 24);
  assert.equal(evaluated.derived.stateTransitionNewStateRoot.toString(), input.newStateRoot);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
});

test('builds Cairo executable arguments for linked ProcessMessages step proof', () => {
  const input = buildStatefulEcdhSignatureFixture();
  const evaluated = evaluateProcessMessagesStateful(input);
  const cairoInput = buildCairoProcessMessageStepWithEcdhSignatureInput(input, 3, evaluated);
  const args = serializeCairoProcessMessageStepWithEcdhSignatureExecutableArgs(cairoInput);
  const transition = evaluated.state.transitions[3];

  assert.equal(cairoInput.public_output.length, 27);
  assert.equal(cairoInput.publicFields.messageIndex, 3n);
  assert.equal(cairoInput.publicFields.previousMessageHash, evaluated.derived.messageHashChain[3]);
  assert.equal(cairoInput.publicFields.nextMessageHash, evaluated.derived.messageHashChain[4]);
  assert.equal(cairoInput.publicFields.currentStateRoot, transition.input.currentStateRoot);
  assert.equal(cairoInput.publicFields.newStateRoot, transition.derived.newStateRoot);
  assert.equal(cairoInput.publicFields.currentStateCommitment, evaluated.publicFields.currentStateCommitment);
  assert.equal(cairoInput.publicFields.newStateCommitment, evaluated.publicFields.newStateCommitment);
  assert.ok(args.length > 10000);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
});

test('builds Cairo executable arguments for deeply split ProcessMessages proofs', () => {
  const input = buildStatefulEcdhSignatureFixture();
  const evaluated = evaluateProcessMessagesStateful(input);
  const coordKey = buildCairoProcessMessageCoordKeyInput(input, evaluated);
  const ecdh = buildCairoProcessMessageEcdhInput(input, 3, evaluated);
  const signature = buildCairoProcessMessageSignatureInput(input, 3, evaluated);
  const core = buildCairoProcessMessageStepCoreInput(input, 3, evaluated);
  const coordArgs = serializeCairoProcessMessageCoordKeyExecutableArgs(coordKey);
  const ecdhArgs = serializeCairoProcessMessageEcdhExecutableArgs(ecdh);
  const signatureArgs = serializeCairoProcessMessageSignatureExecutableArgs(signature);
  const coreArgs = serializeCairoProcessMessageStepCoreExecutableArgs(core);

  assert.equal(coordKey.public_output.length, 10);
  assert.equal(ecdh.public_output.length, 13);
  assert.equal(signature.public_output.length, 17);
  assert.equal(core.public_output.length, 43);
  assert.equal(ecdh.publicFields.messageIndex, 3n);
  assert.equal(signature.publicFields.messageIndex, 3n);
  assert.equal(core.publicFields.messageIndex, 3n);
  assert.equal(coordKey.publicFields.coordPrivKeyHash, ecdh.publicFields.coordPrivKeyHash);
  assert.equal(coordKey.publicFields.coordPrivKeyHash, core.publicFields.coordPrivKeyHash);
  assert.equal(ecdh.publicFields.encPubKeyHash, core.publicFields.encPubKeyHash);
  assert.equal(ecdh.publicFields.sharedKeyHash, core.publicFields.sharedKeyHash);
  assert.equal(signature.publicFields.pubKeyHash, core.publicFields.signaturePubKeyHash);
  assert.equal(signature.publicFields.r8Hash, core.publicFields.signatureR8Hash);
  assert.equal(signature.publicFields.packedCommandHash, core.publicFields.packedCommandHash);
  assert.equal(signature.publicFields.cmdSigS, core.publicFields.cmdSigS);
  assert.equal(signature.publicFields.isSignatureValid, core.publicFields.isSignatureValid);
  assert.ok(coordArgs.length < ecdhArgs.length);
  assert.ok(coreArgs.length < serializeCairoProcessMessageStepWithEcdhSignatureExecutableArgs(
    buildCairoProcessMessageStepWithEcdhSignatureInput(input, 3, evaluated),
  ).length);
  assert.ok([...coordArgs, ...ecdhArgs, ...signatureArgs, ...coreArgs].every((value) => /^0x[0-9a-f]+$/.test(value)));
});

test('rejects a stateful ProcessMessages signature witness that does not match isSignatureValid', () => {
  const input = buildStatefulEcdhSignatureFixture();
  input.processOneWitnesses[0].isSignatureValid = '0';
  input.processOneWitnesses[0].isValid = '0';

  assert.throws(
    () => buildCairoProcessMessagesStatefulWithEcdhSignatureInput(input),
    /currentStateRoot mismatch|signature verification result does not match/,
  );
});

test('rejects a stateful ProcessMessages ECDH witness when coordPrivKey does not match coordPubKey', () => {
  const input = buildStatefulEcdhFixture();
  input.coordPrivKey = '6';

  assert.throws(
    () => buildCairoProcessMessagesStatefulWithEcdhInput(input),
    /coordPrivKey mismatch|coordPrivKey does not match coordPubKey/,
  );
});

test('rejects a stateful ProcessMessages ECDH transcript that does not match its ProcessOne shared key', () => {
  const input = buildStatefulEcdhFixture();
  input.ecdhInputs = ecdhInputsFor(input);
  input.ecdhInputs[0].privKey = '6';

  assert.throws(
    () => buildCairoProcessMessagesStatefulWithEcdhInput(input),
    /ECDH shared key does not match ProcessOne 0 sharedKey witness/,
  );
});

test('rejects a stateful ProcessMessages witness with tampered active decrypt flag', () => {
  const input = buildStatefulEcdhSignatureFixture();
  input.processOneWitnesses[0].isDecryptionActive =
    input.processOneWitnesses[0].isDecryptionActive === '1' ? '0' : '1';

  assert.throws(
    () => evaluateProcessMessagesStateful(input),
    /isDecryptionActive mismatch/,
  );
});

test('accepts an empty message only when its ProcessOne transition is invalid', () => {
  const input = buildStatefulFixture();
  input.encPubKeys[2][0] = '0';
  recomputeProcessMessagesBoundary(input);

  const evaluated = evaluateProcessMessagesStateful(input);
  assert.equal(evaluated.state.transitions[2].input.isValid, 0n);
});

test('rejects an empty message driving a valid ProcessOne transition', () => {
  const input = buildStatefulFixture();
  input.encPubKeys[0][0] = '0';
  recomputeProcessMessagesBoundary(input);

  assert.throws(
    () => evaluateProcessMessagesStateful(input),
    /empty message 0 cannot drive a valid ProcessOne transition/,
  );
});
