import { TREE_ARITY } from '../constants.mjs';
import {
  addNewKeyInputHash,
  processDeactivateInputHash,
  processMessagesInputHash,
} from '../compat/encoding.mjs';
import {
  BABYJUB_BASE8,
  babyjubAdd,
  babyjubScalarMul,
  poseidonSignatureMessage,
} from '../compat/babyjub.mjs';
import { hash5, hash10, hashLeftRight } from '../compat/poseidon.mjs';
import { evaluateProcessDeactivateOne, elGamalDecryptPoint } from '../deactivate/process-deactivate-one.mjs';
import { evaluateProcessOneStateTransition, packCommandData, poseidonEncryptWithoutCheck7 } from '../msg/process-one.mjs';
import { packProcessMessagesVals, processMessageHashChain } from '../msg/process-messages.mjs';
import { processDeactivateMessageHashChain } from '../deactivate/process-deactivate-messages.mjs';
import { requireZkKitPackage } from '../compat/zk-kit-require.mjs';

export const SMALL_SYNTHETIC_CIRCUITS = Object.freeze([
  'add-new-key',
  'process-messages',
  'process-deactivate',
]);

let eddsaPoseidon;

function loadEddsaPoseidon() {
  if (eddsaPoseidon) {
    return eddsaPoseidon;
  }
  eddsaPoseidon = requireZkKitPackage('@zk-kit/eddsa-poseidon');
  return eddsaPoseidon;
}

function derivePublicKeyFromSecret(secretKey) {
  return loadEddsaPoseidon().derivePublicKey(secretKey).map(BigInt);
}

function signPoseidonMessage(secretKey, message) {
  return loadEddsaPoseidon().signMessage(secretKey, message);
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

function buildActiveCiphertext(coordPrivKey, seed) {
  const c1 = babyjubScalarMul(BABYJUB_BASE8, BigInt(seed));
  const c2 = babyjubScalarMul(c1, coordPrivKey);
  return { c1, c2 };
}

function buildProcessMessagesStateLeaf(
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

function buildProcessMessagesState({ sharedKeys, signatureSecretKeys } = {}) {
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
    if (signatureSecretKeys?.[i]) {
      pubKeysByState.set(commands[i].stateIndex, derivePublicKeyFromSecret(signatureSecretKeys[i]));
      if (!commands[i].isValid) {
        pubKeysByState.set(24, derivePublicKeyFromSecret(signatureSecretKeys[i]));
      }
    }
  }
  for (const stateIndex of touchedStateIndexes) {
    const voteRoot = pathFor(voteLeavesByState[stateIndex], 1, 0).root;
    stateLeaves[stateIndex] = buildProcessMessagesStateLeaf(
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
    const signaturePreimage = command.isValid
      ? packedCommand
      : [packedCommand[0] + 1n, packedCommand[1], packedCommand[2]];
    const signature = signatureSecretKeys?.[i]
      ? signPoseidonMessage(signatureSecretKeys[i], poseidonSignatureMessage(signaturePreimage))
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

  return decimalize({
    currentStateRoot,
    coordPrivKey,
    activeStateRoot,
    newStateRoot: pathFor(stateLeafHashes, 2, 0).root,
    processOneWitnesses,
  });
}

function buildProcessMessagesBoundary({ state, coordPrivKey, encPubKeys }) {
  const packedVals = packProcessMessagesVals({
    isQuadraticCost: 1n,
    numSignUps: 20n,
    maxVoteOptions: 5n,
  });
  const coordPubKey = babyjubScalarMul(BABYJUB_BASE8, BigInt(coordPrivKey));
  const coordPubKeyHash = hashLeftRight(coordPubKey[0], coordPubKey[1]);
  const msgs = state.processOneWitnesses.map((witness) => witness.msg.map(BigInt));
  const batchStartHash = 123n;
  const { endHash: batchEndHash } = processMessageHashChain(msgs, encPubKeys, batchStartHash);
  const currentStateSalt = 701n;
  const newStateSalt = 702n;
  const deactivateRoot = 703n;
  const currentStateCommitment = hashLeftRight(BigInt(state.currentStateRoot), currentStateSalt);
  const newStateCommitment = hashLeftRight(BigInt(state.newStateRoot), newStateSalt);
  const deactivateCommitment = hashLeftRight(BigInt(state.activeStateRoot), deactivateRoot);
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
    encPubKeys,
    coordPrivKey,
  });
}

export function buildSmallProcessMessagesFixture() {
  const coordPrivKey = 5n;
  const encPubKeys = [2n, 3n, 4n, 6n, 7n].map((scalar) =>
    babyjubScalarMul(BABYJUB_BASE8, scalar),
  );
  const sharedKeys = encPubKeys.map((pubKey) => babyjubScalarMul(pubKey, coordPrivKey));
  const signatureSecretKeys = [
    Buffer.from([1, 2, 3, 4, 5]),
    Buffer.from([2, 3, 4, 5, 6]),
    Buffer.from([5, 6, 7, 8, 9]),
    Buffer.from([3, 4, 5, 6, 7]),
    Buffer.from([4, 5, 6, 7, 8]),
  ];
  const state = buildProcessMessagesState({ sharedKeys, signatureSecretKeys });
  return buildProcessMessagesBoundary({ state, coordPrivKey, encPubKeys });
}

export function buildSmallAddNewKeyFixture() {
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

function identityDecryptCiphertext(coordPrivKey, randomScalar) {
  const c1 = babyjubScalarMul(BABYJUB_BASE8, randomScalar);
  const c2 = babyjubScalarMul(c1, coordPrivKey);
  const decrypt = elGamalDecryptPoint(c1, c2, coordPrivKey);
  if (decrypt.decryptedPoint[0] !== 0n || decrypt.isOdd !== 0n) {
    throw new Error('identity ciphertext did not decrypt to the expected active state');
  }
  return { c1, c2 };
}

export function buildSmallProcessDeactivateFixture() {
  const coordPrivKey = 5n;
  const coordPubKey = babyjubScalarMul(BABYJUB_BASE8, coordPrivKey);
  const expectedPollId = 77n;
  const deactivateIndex0 = 40n;
  const emptyStateLeafHash = hash10([0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
  const stateLeafHashes = Array.from({ length: 25 }, () => emptyStateLeafHash);
  const stateLeaves = [];

  for (let i = 0; i < 5; i += 1) {
    const secretKey = Buffer.from([21 + i, 34 + i, 55 + i, 89 + i, 144 + i]);
    const statePubKey = derivePublicKeyFromSecret(secretKey);
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
    const signature = signPoseidonMessage(secretKey, poseidonSignatureMessage(packedCmd));
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

export function buildSmallSyntheticFixture(circuit) {
  if (circuit === 'add-new-key') {
    return buildSmallAddNewKeyFixture();
  }
  if (circuit === 'process-messages') {
    return buildSmallProcessMessagesFixture();
  }
  if (circuit === 'process-deactivate') {
    return buildSmallProcessDeactivateFixture();
  }
  throw new Error(`unsupported small synthetic fixture circuit: ${circuit}`);
}
