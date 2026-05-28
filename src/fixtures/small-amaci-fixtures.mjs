import {
  ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN,
  ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN,
  ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN,
  ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN,
  MAX_VOTES,
  PROCESS_DEACTIVATE_NATIVE_INPUT_HASH_DOMAIN,
  PROCESS_MESSAGES_NATIVE_INPUT_HASH_DOMAIN,
  TREE_ARITY,
} from '../constants.mjs';
import {
  STARK_NATIVE_COMMAND_SIGNATURE_DOMAIN,
  STARK_NATIVE_DEACTIVATE_SIGNATURE_DOMAIN,
  STARK_NATIVE_DEACTIVATE_STREAM_DOMAIN,
  starkElGamalEncryptPoint,
  starkPointAdd,
  starkPointWithXParity,
  starkPublicKeyPoint,
  starkPoseidonEncryptWithoutCheck7,
  starkScalarMul,
  starkSignCommand,
} from '../stark-native-crypto.mjs';
import {
  nativeHash5,
  nativeHash10,
  nativeHashFelts,
  nativeHashPoint,
} from '../native-hash.mjs';
import { evaluateProcessDeactivateOne, elGamalDecryptPoint } from '../deactivate/process-deactivate-one.mjs';
import { evaluateNativeTallyVotes } from '../tally/native-tally-votes.mjs';
import {
  evaluateProcessOneStateTransition,
  packCommandData,
  poseidonEncryptWithoutCheck7,
} from '../msg/process-one.mjs';
import {
  evaluateProcessMessagesStateful,
  packProcessMessagesVals,
  processMessageHashChain,
} from '../msg/process-messages.mjs';
import { evaluateNativeProcessMessagesBoundary } from '../msg/native-process-messages.mjs';
import {
  nativeProcessMessageTransitionContexts,
} from '../msg/native-process-roots.mjs';
import { processDeactivateMessageHashChain } from '../deactivate/process-deactivate-messages.mjs';
import {
  evaluateNativeProcessDeactivateMessagesBoundary,
} from '../deactivate/native-process-deactivate-messages.mjs';

export const SMALL_SYNTHETIC_CIRCUITS = Object.freeze([
  'add-new-key',
  'process-messages',
  'process-deactivate',
]);

function secretToScalar(secretKey) {
  if (typeof secretKey === 'bigint' || typeof secretKey === 'number' || typeof secretKey === 'string') {
    return BigInt(secretKey);
  }
  if (Buffer.isBuffer(secretKey) || secretKey instanceof Uint8Array) {
    return BigInt(`0x${Buffer.from(secretKey).toString('hex')}`);
  }
  throw new Error('unsupported STARK native secret key format');
}

function derivePublicKeyFromSecret(secretKey) {
  return starkPublicKeyPoint(secretToScalar(secretKey));
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

function buildActiveCiphertext(coordPrivKey, seed) {
  const coordPubKey = starkPublicKeyPoint(coordPrivKey);
  const { point: activePoint } = starkPointWithXParity(0n, BigInt(seed) + 1000n);
  const encrypted = starkElGamalEncryptPoint(activePoint, coordPubKey, BigInt(seed));
  return { c1: encrypted.c1, c2: encrypted.c2, decryptedPoint: activePoint };
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

const DEFAULT_PROCESS_MESSAGES_COMMANDS = Object.freeze([
  { isValid: true, stateIndex: 1, voteOptionIndex: 0, newVoteWeight: 31n },
  { isValid: true, stateIndex: 7, voteOptionIndex: 3, newVoteWeight: 37n },
  { isValid: false, stateIndex: 8, voteOptionIndex: 2, newVoteWeight: 41n },
]);

function normalizeProcessMessageCommands(commands) {
  return commands.map((command) => ({
    isEmpty: Boolean(command.isEmpty),
    isValid: command.isEmpty ? false : command.isValid,
    stateIndex: Number(command.stateIndex),
    voteOptionIndex: Number(command.voteOptionIndex),
    newVoteWeight: BigInt(command.newVoteWeight),
    invalidStateIndex: command.invalidStateIndex === undefined
      ? 24
      : Number(command.invalidStateIndex),
  }));
}

function buildProcessMessagesState({
  sharedKeys,
  signatureSecretKeys,
  commands = DEFAULT_PROCESS_MESSAGES_COMMANDS,
  numSignUps = 20n,
  maxVoteOptions = 5n,
  expectedPollId = 77n,
  initialVoteLeavesByState: initialVoteLeavesByStateOption,
  initialStateLeaves: initialStateLeavesOption,
  initialActiveLeaves: initialActiveLeavesOption,
} = {}) {
  const isQuadraticCost = 1n;
  const coordPrivKey = 5n;
  const normalizedCommands = normalizeProcessMessageCommands(commands);
  const emptyStateLeaf = Array.from({ length: 10 }, () => 0n);
  const voteLeavesByState = initialVoteLeavesByStateOption === undefined
    ? Array.from({ length: 25 }, (_, stateIndex) => [
      BigInt(stateIndex + 1),
      BigInt(stateIndex + 2),
      BigInt(stateIndex + 3),
      BigInt(stateIndex + 4),
      BigInt(stateIndex + 5),
    ])
    : initialVoteLeavesByStateOption.map((row) => row.map(BigInt));
  const stateLeaves = initialStateLeavesOption === undefined
    ? Array.from({ length: 25 }, () => emptyStateLeaf.slice())
    : initialStateLeavesOption.map((row) => row.map(BigInt));
  const touchedStateIndexes = [
    ...new Set(
      normalizedCommands.map((command) =>
        command.isValid ? command.stateIndex : command.invalidStateIndex,
      ),
    ),
  ];
  const pubKeysByState = new Map();

  for (let i = 0; i < normalizedCommands.length; i += 1) {
    const command = normalizedCommands[i];
    if (signatureSecretKeys?.[i]) {
      pubKeysByState.set(command.stateIndex, derivePublicKeyFromSecret(signatureSecretKeys[i]));
      if (!command.isValid) {
        pubKeysByState.set(command.invalidStateIndex, derivePublicKeyFromSecret(signatureSecretKeys[i]));
      }
    }
  }
  for (const stateIndex of touchedStateIndexes) {
    if (stateLeaves[stateIndex].every((value) => value === 0n)) {
      const voteRoot = pathFor(voteLeavesByState[stateIndex], 1, 0).root;
      stateLeaves[stateIndex] = buildProcessMessagesStateLeaf(
        stateIndex + 10,
        voteRoot,
        coordPrivKey,
        pubKeysByState.get(stateIndex),
      );
    }
  }

  const activeLeaves = initialActiveLeavesOption === undefined
    ? Array.from({ length: 25 }, () => 0n)
    : initialActiveLeavesOption.map(BigInt);
  const activeStateRoot = pathFor(activeLeaves, 2, 0).root;
  let stateLeafHashes = stateLeaves.map((leaf, index) => nativeHash10(leaf, `stateLeaf[${index}]`));
  const currentStateRoot = pathFor(stateLeafHashes, 2, 0).root;
  const initialStateLeaves = stateLeaves.map((leaf) => leaf.slice());
  const initialVoteLeavesByState = voteLeavesByState.map((row) => row.slice());
  const processOneWitnesses = Array.from({ length: normalizedCommands.length });

  for (let i = normalizedCommands.length - 1; i >= 0; i -= 1) {
    const command = normalizedCommands[i];
    const stateIndex = command.isValid ? command.stateIndex : command.invalidStateIndex;
    const voteOptionIndex = command.isValid ? command.voteOptionIndex : 0;
    const stateTree = pathFor(stateLeafHashes, 2, stateIndex);
    const activeTree = pathFor(activeLeaves, 2, stateIndex);
    const voteTree = pathFor(voteLeavesByState[stateIndex], 1, voteOptionIndex);
    const currentVoteWeight = voteLeavesByState[stateIndex][voteOptionIndex];
    const sharedKey = sharedKeys?.[i] ?? [BigInt(1100 + i), BigInt(1200 + i)];
    let cmdNonce;
    let cmdNewVoteWeight;
    let cmdVoteOptionIndex;
    let cmdStateIndex;
    let cmdPollId;
    let cmdNewPubKey;
    let cmdSalt;
    let cmdSigR8;
    let cmdSigS;
    let packedCommand;
    let decryptedCommand;
    let msg;
    let newBalance;
    let newSlNonce;
    if (command.isEmpty) {
      cmdNonce = stateLeaves[stateIndex][4] + 1n;
      cmdNewVoteWeight = 0n;
      cmdVoteOptionIndex = 0n;
      cmdStateIndex = BigInt(command.stateIndex);
      cmdPollId = expectedPollId;
      cmdNewPubKey = starkPublicKeyPoint(BigInt(500 + i));
      cmdSalt = BigInt(700 + i);
      packedCommand = [
        packCommandData({
          pollId: expectedPollId,
          newVoteWeight: 0n,
          voteOptionIndex: 0n,
          stateIndex: BigInt(command.stateIndex),
          nonce: cmdNonce,
        }),
        ...cmdNewPubKey,
      ];
      const fallbackRPoint = starkPublicKeyPoint(BigInt(800 + i));
      cmdSigR8 = fallbackRPoint;
      cmdSigS = BigInt(1000 + i);
      decryptedCommand = [packedCommand[0], ...cmdNewPubKey, cmdSalt, ...cmdSigR8, cmdSigS];
      msg = poseidonEncryptWithoutCheck7(decryptedCommand, sharedKey);
      newBalance = stateLeaves[stateIndex][2];
      newSlNonce = stateLeaves[stateIndex][4];
    } else {
      cmdNonce = stateLeaves[stateIndex][4] + 1n;
      cmdNewVoteWeight = command.newVoteWeight;
      cmdVoteOptionIndex = BigInt(command.voteOptionIndex);
      cmdStateIndex = BigInt(command.stateIndex);
      cmdPollId = expectedPollId;
      const computedNewBalance =
        stateLeaves[stateIndex][2] +
        processOneCost(isQuadraticCost, currentVoteWeight) -
        processOneCost(isQuadraticCost, command.newVoteWeight);
      newBalance = command.isValid ? computedNewBalance : (computedNewBalance < 0n ? 0n : computedNewBalance);
      cmdNewPubKey = starkPublicKeyPoint(BigInt(500 + i));
      cmdSalt = BigInt(700 + i);
      packedCommand = [
        packCommandData({
          pollId: expectedPollId,
          newVoteWeight: command.newVoteWeight,
          voteOptionIndex: BigInt(command.voteOptionIndex),
          stateIndex: BigInt(command.stateIndex),
          nonce: cmdNonce,
        }),
        ...cmdNewPubKey,
      ];
      const fallbackRPoint = starkPublicKeyPoint(BigInt(800 + i));
      const signature = signatureSecretKeys?.[i]
        ? starkSignCommand(
          secretToScalar(signatureSecretKeys[i]),
          command.isValid ? packedCommand : [packedCommand[0] + 1n, packedCommand[1], packedCommand[2]],
          cmdSalt,
          STARK_NATIVE_COMMAND_SIGNATURE_DOMAIN,
        )
        : { r: fallbackRPoint[0], rPoint: fallbackRPoint, s: BigInt(1000 + i) };
      cmdSigR8 = signature.rPoint.map(BigInt);
      cmdSigS = BigInt(signature.s);
      decryptedCommand = [packedCommand[0], ...cmdNewPubKey, cmdSalt, ...cmdSigR8, cmdSigS];
      msg = poseidonEncryptWithoutCheck7(decryptedCommand, sharedKey);
      newSlNonce = cmdNonce;
    }
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
      cmdStateIndex,
      cmdVoteOptionIndex,
      cmdNewVoteWeight,
      cmdNonce,
      cmdPollId,
      cmdNewPubKey,
      newBalance,
      newSlNonce,
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
    initialStateLeaves,
    initialVoteLeavesByState,
    initialActiveLeaves: activeLeaves,
    finalStateLeaves: stateLeaves,
    finalVoteLeavesByState: voteLeavesByState,
    numSignUps,
    maxVoteOptions,
    expectedPollId,
  });
}

function buildProcessMessagesBoundary({ state, coordPrivKey, encPubKeys }) {
  const numSignUps = BigInt(state.numSignUps ?? 20n);
  const maxVoteOptions = BigInt(state.maxVoteOptions ?? 5n);
  const expectedPollId = BigInt(state.expectedPollId ?? 77n);
  const packedVals = packProcessMessagesVals({
    isQuadraticCost: 1n,
    numSignUps,
    maxVoteOptions,
  });
  const coordPubKey = starkPublicKeyPoint(BigInt(coordPrivKey));
  const coordPubKeyHash = nativeHashPoint(coordPubKey, 'coordPubKey');
  const msgs = state.processOneWitnesses.map((witness) => witness.msg.map(BigInt));
  const batchStartHash = BigInt(state.batchStartHash ?? 0n);
  const { endHash: batchEndHash } = processMessageHashChain(msgs, encPubKeys, batchStartHash);
  const currentStateSalt = BigInt(state.currentStateSalt ?? 701n);
  const newStateSalt = BigInt(state.newStateSalt ?? 702n);
  const deactivateRoot = BigInt(state.deactivateRoot ?? 703n);
  const currentStateCommitment = nativeHashFelts(
    [BigInt(state.currentStateRoot), currentStateSalt],
    'currentStateCommitment',
  );
  const newStateCommitment = nativeHashFelts(
    [BigInt(state.newStateRoot), newStateSalt],
    'newStateCommitment',
  );
  const deactivateCommitment = nativeHashFelts(
    [BigInt(state.activeStateRoot), deactivateRoot],
    'deactivateCommitment',
  );
  const inputHash = nativeHashFelts([
    PROCESS_MESSAGES_NATIVE_INPUT_HASH_DOMAIN,
    packedVals,
    coordPubKeyHash,
    batchStartHash,
    batchEndHash,
    currentStateCommitment,
    newStateCommitment,
    deactivateCommitment,
    expectedPollId,
  ], 'processMessagesInputHash');

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

function smallProcessMessageCryptoInputs() {
  const coordPrivKey = 5n;
  const encPubKeys = [2n, 3n, 4n].map((scalar) => starkPublicKeyPoint(scalar));
  const sharedKeys = encPubKeys.map((pubKey) => starkScalarMul(pubKey, coordPrivKey));
  const signatureSecretKeys = [
    Buffer.from([1, 2, 3, 4, 5]),
    Buffer.from([2, 3, 4, 5, 6]),
    Buffer.from([5, 6, 7, 8, 9]),
  ];
  return { coordPrivKey, encPubKeys, sharedKeys, signatureSecretKeys };
}

export function buildSmallProcessMessagesFixture(options = {}) {
  const defaults = smallProcessMessageCryptoInputs();
  const coordPrivKey = BigInt(options.coordPrivKey ?? defaults.coordPrivKey);
  const encPubKeys = options.encPubKeys === undefined
    ? defaults.encPubKeys
    : options.encPubKeys.map((point) => point.map(BigInt));
  const sharedKeys = options.sharedKeys === undefined
    ? encPubKeys.map((pubKey) =>
      pubKey[0] === 0n && pubKey[1] === 0n
        ? [0n, 0n]
        : starkScalarMul(pubKey, coordPrivKey),
    )
    : options.sharedKeys.map((point) => point.map(BigInt));
  const signatureSecretKeys = options.signatureSecretKeys ?? defaults.signatureSecretKeys;
  const state = buildProcessMessagesState({
    sharedKeys,
    signatureSecretKeys,
    commands: options.commands,
    numSignUps: options.numSignUps,
    maxVoteOptions: options.maxVoteOptions,
    expectedPollId: options.expectedPollId,
    initialVoteLeavesByState: options.initialVoteLeavesByState,
    initialStateLeaves: options.initialStateLeaves,
    initialActiveLeaves: options.initialActiveLeaves,
  });
  if (options.deactivateRoot !== undefined) {
    state.deactivateRoot = BigInt(options.deactivateRoot).toString();
  }
  for (const key of ['batchStartHash', 'currentStateSalt', 'newStateSalt']) {
    if (options[key] !== undefined) {
      state[key] = BigInt(options[key]).toString();
    }
  }
  return buildProcessMessagesBoundary({ state, coordPrivKey, encPubKeys });
}

export function buildSmallNativeRoundFixture() {
  const commands = [
    { isValid: true, stateIndex: 0, voteOptionIndex: 0, newVoteWeight: 2n },
    { isValid: true, stateIndex: 1, voteOptionIndex: 1, newVoteWeight: 4n },
    { isValid: true, stateIndex: 2, voteOptionIndex: 2, newVoteWeight: 6n },
  ];
  const processMessagesDraft = buildSmallProcessMessagesFixture({ commands });
  const processMessagesEvaluated = evaluateNativeProcessMessagesBoundary(processMessagesDraft);
  const processMessages = processMessagesDraft;
  const stateResult = evaluateProcessMessagesStateful(processMessagesDraft).state;
  const transitionContexts = nativeProcessMessageTransitionContexts(stateResult, processMessagesDraft);
  const contextsByStateIndex = new Map();
  for (let index = 0; index < transitionContexts.length; index += 1) {
    const stateIndex = Number(stateResult.transitions[index].derived.stateIndex);
    if (!contextsByStateIndex.has(stateIndex)) {
      contextsByStateIndex.set(stateIndex, transitionContexts[index]);
    }
  }
  const finalStateLeaves = [];
  const finalVotes = [];
  for (let stateIndex = 0; stateIndex < TREE_ARITY; stateIndex += 1) {
    const context = contextsByStateIndex.get(stateIndex);
    finalStateLeaves.push(context?.newStateLeaf ?? Array.from({ length: 10 }, () => 0n));
    finalVotes.push(
      context === undefined
        ? Array.from({ length: TREE_ARITY }, () => 0n)
        : processMessagesDraft.finalVoteLeavesByState[stateIndex].map(BigInt),
    );
  }

  const batchZeroContext = contextsByStateIndex.get(0);
  const tallyDraft = {
    packedVals: (20n << 32n).toString(),
    stateRoot: batchZeroContext.newStateRoot.toString(),
    stateSalt: processMessages.newStateSalt,
    stateLeaf: finalStateLeaves,
    statePathElements: [batchZeroContext.newStateLeafPathElements[1]],
    votes: finalVotes,
    currentResults: Array.from({ length: 5 }, () => 0n),
    currentResultsRootSalt: '0',
    newResultsRootSalt: '901',
  };
  const tallyEvaluated = evaluateNativeTallyVotes(tallyDraft);
  const tally = {
    ...tallyDraft,
    stateCommitment: tallyEvaluated.publicFields.stateCommitment,
    currentTallyCommitment: tallyEvaluated.publicFields.currentTallyCommitment,
    newTallyCommitment: tallyEvaluated.publicFields.newTallyCommitment,
    inputHash: tallyEvaluated.publicFields.inputHash,
  };

  return decimalize({
    processMessages,
    tally,
    chain: {
      initialStateCommitment: processMessagesEvaluated.publicFields.currentStateCommitment,
      rawProcessMessagesCurrentStateCommitment: processMessages.currentStateCommitment,
      initialDeactivateCommitment: processMessagesEvaluated.publicFields.deactivateCommitment,
      processMessagesNewStateCommitment: processMessagesEvaluated.publicFields.newStateCommitment,
      tallyStateCommitment: tally.stateCommitment,
      processMessagesToTallyStateMatches:
        processMessagesEvaluated.publicFields.newStateCommitment
          === tallyEvaluated.publicFields.stateCommitment,
      initialTallyCommitment: tally.currentTallyCommitment,
      finalTallyCommitment: tally.newTallyCommitment,
    },
  });
}

export function buildSmallAddNewKeyFixture(options = {}) {
  const coordPubKey = options.coordPubKey?.map(BigInt) ?? starkPublicKeyPoint(5n);
  const oldPrivateKey = BigInt(options.oldPrivateKey ?? 7n);
  const pollId = BigInt(options.pollId ?? 77n);
  const c1 = options.c1?.map(BigInt) ?? starkPublicKeyPoint(2n);
  const c2 = options.c2?.map(BigInt) ?? starkPublicKeyPoint(3n);
  const randomVal = BigInt(options.randomVal ?? 11n);
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
    'addNewKeyDeactivateLeaf',
  );
  const deactivateIndex = Number(options.deactivateIndex ?? 42);
  const leaves = options.deactivateLeaves === undefined
    ? Array.from({ length: TREE_ARITY ** 4 }, () => 0n)
    : options.deactivateLeaves.map(BigInt);
  if (leaves[deactivateIndex] !== 0n && leaves[deactivateIndex] !== deactivateLeaf) {
    throw new Error('deactivate leaf at add-new-key index does not match c1/c2/shared key');
  }
  leaves[deactivateIndex] = deactivateLeaf;
  const deactivateTree = pathFor(leaves, 4, deactivateIndex);
  const nullifier = nativeHashFelts(
    [ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN, oldPrivateKey, pollId],
    'addNewKeyNullifier',
  );
  const newPubKey = options.newPubKey?.map(BigInt) ?? starkPublicKeyPoint(BigInt(options.newPrivateKey ?? 13n));
  const coordPubKeyHash = nativeHashPoint(coordPubKey, 'coordPubKey');
  const d1Hash = nativeHashPoint(d1, 'd1');
  const d2Hash = nativeHashPoint(d2, 'd2');
  const rerandomizeBindingHash = nativeHashFelts(
    [ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN, coordPubKeyHash, c1Hash, c2Hash, d1Hash, d2Hash],
    'addNewKeyRerandomizeBinding',
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

function identityDecryptCiphertext(coordPrivKey, randomScalar) {
  return parityDecryptCiphertext(coordPrivKey, randomScalar, 0n);
}

function inactiveDecryptCiphertext(coordPrivKey, randomScalar) {
  return parityDecryptCiphertext(coordPrivKey, randomScalar, 1n);
}

function parityDecryptCiphertext(coordPrivKey, randomScalar, parity) {
  const coordPubKey = starkPublicKeyPoint(coordPrivKey);
  const { point: activePoint } = starkPointWithXParity(parity, BigInt(randomScalar) + 2000n);
  const { c1, c2 } = starkElGamalEncryptPoint(activePoint, coordPubKey, randomScalar);
  const decrypt = elGamalDecryptPoint(c1, c2, coordPrivKey);
  if (decrypt.isOdd !== BigInt(parity)) {
    throw new Error('identity ciphertext did not decrypt to the expected parity');
  }
  return { c1, c2 };
}

export function buildSmallProcessDeactivateFixture(options = {}) {
  const coordPrivKey = 5n;
  const coordPubKey = starkPublicKeyPoint(coordPrivKey);
  const expectedPollId = 77n;
  const deactivateIndex0 = 40n;
  const stateIndexes = options.stateIndexes ?? [0, 1, 2];
  if (!Array.isArray(stateIndexes) || stateIndexes.length < 1 || stateIndexes.length > 3) {
    throw new Error('stateIndexes must contain 1 to 3 entries');
  }
  const realStateIndexes = stateIndexes.map(Number);
  const paddingStateIndex = Number(options.paddingStateIndex ?? 24);
  const paddedStateIndexes = realStateIndexes.slice();
  while (paddedStateIndexes.length < 3) {
    paddedStateIndexes.push(paddingStateIndex);
  }
  const signupStateIndexes = (options.signupStateIndexes ?? realStateIndexes).map(Number);
  const privateKeysByState = new Map(
    Object.entries(options.privateKeysByState ?? {}).map(([key, value]) => [Number(key), BigInt(value)]),
  );
  const emptyStateLeafHash = nativeHash10(
    [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
    'emptyStateLeaf',
  );
  const stateLeafHashes = Array.from({ length: 25 }, () => emptyStateLeafHash);
  const stateEntriesByIndex = new Map();

  for (let i = 0; i < signupStateIndexes.length; i += 1) {
    const stateIndex = Number(signupStateIndexes[i]);
    const secretKey = privateKeysByState.get(stateIndex) ?? BigInt(1000 + stateIndex);
    const statePubKey = derivePublicKeyFromSecret(secretKey);
    const currentCiphertext = identityDecryptCiphertext(coordPrivKey, BigInt(20 + stateIndex));
    const stateLeaf = [
      ...statePubKey,
      2000n + BigInt(stateIndex),
      0n,
      0n,
      currentCiphertext.c1[0],
      currentCiphertext.c1[1],
      currentCiphertext.c2[0],
      currentCiphertext.c2[1],
      0n,
    ];
    stateEntriesByIndex.set(stateIndex, { secretKey, stateIndex, stateLeaf });
    stateLeafHashes[stateIndex] = nativeHash10(stateLeaf, `deactivateStateLeaf[${stateIndex}]`);
  }
  if (realStateIndexes.length < 3 && !stateEntriesByIndex.has(paddingStateIndex)) {
    const secretKey = BigInt(9000 + paddingStateIndex);
    const statePubKey = derivePublicKeyFromSecret(secretKey);
    const currentCiphertext = identityDecryptCiphertext(coordPrivKey, BigInt(200 + paddingStateIndex));
    const stateLeaf = [
      ...statePubKey,
      1n,
      0n,
      0n,
      currentCiphertext.c1[0],
      currentCiphertext.c1[1],
      currentCiphertext.c2[0],
      currentCiphertext.c2[1],
      0n,
    ];
    stateEntriesByIndex.set(paddingStateIndex, { secretKey, stateIndex: paddingStateIndex, stateLeaf });
    stateLeafHashes[paddingStateIndex] = nativeHash10(stateLeaf, `deactivatePaddingStateLeaf[${paddingStateIndex}]`);
  }
  const stateLeaves = paddedStateIndexes.map((stateIndex) => stateEntriesByIndex.get(stateIndex));

  const stateTree = pathFor(stateLeafHashes, 2, 0);
  const currentStateRoot = stateTree.root;
  const activeLeaves = Array.from({ length: 25 }, () => 0n);
  const deactivateLeaves = Array.from({ length: 625 }, () => 0n);
  const initialActiveLeaves = activeLeaves.slice();
  const initialDeactivateLeaves = deactivateLeaves.slice();
  const currentActiveStateRoot = pathFor(activeLeaves, 2, 0).root;
  const currentDeactivateRoot = pathFor(deactivateLeaves, 4, 0).root;
  const processOneWitnesses = [];
  const deactivateAuthorizations = [];
  const msgs = [];
  const encPubKeys = [];

  let activeRoot = currentActiveStateRoot;
  let deactivateRoot = currentDeactivateRoot;
  for (let i = 0; i < 3; i += 1) {
    const isPadding = i >= realStateIndexes.length;
    const stateIndex = stateLeaves[i].stateIndex;
    const deactivateIndex = Number(deactivateIndex0) + i;
    const { secretKey, stateLeaf } = stateLeaves[i];
    const statePath = pathFor(stateLeafHashes, 2, stateIndex);
    const activePath = pathFor(activeLeaves, 2, stateIndex);
    const deactivatePath = pathFor(deactivateLeaves, 4, deactivateIndex);
    const newCiphertext = isPadding
      ? inactiveDecryptCiphertext(coordPrivKey, BigInt(30 + i))
      : identityDecryptCiphertext(coordPrivKey, BigInt(30 + i));
    const cmdPollId = expectedPollId;
    const packedCmd = [
      packCommandData({
        pollId: cmdPollId,
        newVoteWeight: 0n,
        voteOptionIndex: 0n,
        stateIndex: BigInt(stateIndex),
        nonce: 0n,
      }),
      0n,
      0n,
    ];
    const cmdSalt = 900n + BigInt(i);
    const signature = isPadding
      ? {
        rPoint: starkPublicKeyPoint(BigInt(300 + i)),
        s: BigInt(400 + i),
      }
      : starkSignCommand(
        secretToScalar(secretKey),
        packedCmd,
        cmdSalt,
        STARK_NATIVE_DEACTIVATE_SIGNATURE_DOMAIN,
      );
    const encPubKey = starkPublicKeyPoint(BigInt(70 + i));
    const sharedKey = starkScalarMul(encPubKey, coordPrivKey);
    const decryptedCommand = [
      packedCmd[0],
      packedCmd[1],
      packedCmd[2],
      cmdSalt,
      BigInt(signature.rPoint[0]),
      BigInt(signature.rPoint[1]),
      BigInt(signature.s),
    ];
    const msg = starkPoseidonEncryptWithoutCheck7(
      decryptedCommand,
      sharedKey,
      0n,
      STARK_NATIVE_DEACTIVATE_STREAM_DOMAIN,
    );
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
      cmdPollId,
      cmdSigR8: signature.rPoint.map(BigInt),
      cmdSigS: BigInt(signature.s),
      cmdSalt,
      packedCmd,
      expectedPollId,
      deactivateIndex: BigInt(deactivateIndex),
      deactivateLeafPathElements: deactivatePath.path,
    };
    const evaluated = evaluateProcessDeactivateOne(decimalize(processOne));
    if (!isPadding) {
      activeLeaves[stateIndex] = processOne.newActiveState;
    }
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
    if (!isPadding) {
      deactivateAuthorizations.push({
        oldPrivateKey: secretToScalar(secretKey),
        stateIndex,
        deactivateIndex,
        c1: newCiphertext.c1,
        c2: newCiphertext.c2,
        deactivateLeaf: evaluated.derived.deactivateLeaf,
      });
    }
  }

  const batchStartHash = 0n;
  const { endHash } = processDeactivateMessageHashChain(msgs, encPubKeys, batchStartHash);
  const currentDeactivateCommitment = nativeHashFelts(
    [currentActiveStateRoot, currentDeactivateRoot],
    'currentDeactivateCommitment',
  );
  const newDeactivateCommitment = nativeHashFelts(
    [activeRoot, deactivateRoot],
    'newDeactivateCommitment',
  );
  const coordPubKeyHash = nativeHashPoint(coordPubKey, 'coordPubKey');
  const inputHash = nativeHashFelts([
    PROCESS_DEACTIVATE_NATIVE_INPUT_HASH_DOMAIN,
    deactivateRoot,
    coordPubKeyHash,
    batchStartHash,
    endHash,
    currentDeactivateCommitment,
    newDeactivateCommitment,
    currentStateRoot,
    expectedPollId,
  ], 'processDeactivateInputHash');

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
    initialActiveLeaves,
    initialDeactivateLeaves,
    signupStateLeaves: Array.from(stateEntriesByIndex.values()).map((entry) => entry.stateLeaf),
    signupStateEntries: Object.fromEntries(
      Array.from(stateEntriesByIndex.values()).map((entry) => [entry.stateIndex, entry.stateLeaf]),
    ),
    signupStateIndexes,
    privateKeysByState: Object.fromEntries(
      Array.from(stateEntriesByIndex.values()).map((entry) => [
        entry.stateIndex,
        secretToScalar(entry.secretKey),
      ]),
    ),
    finalActiveLeaves: activeLeaves,
    finalDeactivateLeaves: deactivateLeaves,
    deactivateAuthorizations,
    deactivatedStateIndexes: realStateIndexes.map(BigInt),
  });
}

function buildLinkedProcessDeactivateBoundaryFixture({
  currentActiveStateRoot,
  currentDeactivateRoot,
  newActiveStateRoot,
  newDeactivateRoot,
  currentStateRoot,
  expectedPollId = 77n,
}) {
  const coordPrivKey = 5n;
  const coordPubKey = starkPublicKeyPoint(coordPrivKey);
  const msgs = [
    [101n, 102n, 103n, 104n, 105n, 106n, 107n, 108n, 109n, 0n],
    [201n, 202n, 203n, 204n, 205n, 206n, 207n, 208n, 209n, 0n],
    [301n, 302n, 303n, 304n, 305n, 306n, 307n, 308n, 309n, 0n],
  ];
  const encPubKeys = [80n, 81n, 82n].map((scalar) => starkPublicKeyPoint(scalar));
  const batchStartHash = 321n;
  const { endHash } = processDeactivateMessageHashChain(msgs, encPubKeys, batchStartHash);
  const draft = decimalize({
    newDeactivateRoot,
    coordPubKey,
    batchStartHash,
    batchEndHash: endHash,
    currentActiveStateRoot,
    currentDeactivateRoot,
    newActiveStateRoot,
    currentDeactivateCommitment: 0n,
    newDeactivateCommitment: 0n,
    currentStateRoot,
    expectedPollId,
    msgs,
    encPubKeys,
    coordPrivKey,
  });
  const evaluated = evaluateNativeProcessDeactivateMessagesBoundary(draft);
  return decimalize({
    ...draft,
    batchEndHash: evaluated.publicFields.batchEndHash,
    currentDeactivateCommitment: evaluated.publicFields.currentDeactivateCommitment,
    newDeactivateCommitment: evaluated.publicFields.newDeactivateCommitment,
    inputHash: evaluated.publicFields.inputHash,
  });
}

export function buildSmallNativeLifecycleRoundFixture() {
  const initialVoteLeavesByState = Array.from({ length: 25 }, () =>
    Array.from({ length: TREE_ARITY }, () => 0n),
  );
  const processDeactivate = buildSmallProcessDeactivateFixture({
    stateIndexes: [0, 1, 2],
  });
  const processDeactivateEvaluated = evaluateNativeProcessDeactivateMessagesBoundary(processDeactivate);
  const addNewKeyAuthorization = processDeactivate.deactivateAuthorizations[0];
  const newKeyPrivateKey = 13n;
  const addNewKey = buildSmallAddNewKeyFixture({
    coordPubKey: processDeactivate.coordPubKey,
    oldPrivateKey: addNewKeyAuthorization.oldPrivateKey,
    pollId: processDeactivate.expectedPollId,
    c1: addNewKeyAuthorization.c1,
    c2: addNewKeyAuthorization.c2,
    deactivateIndex: addNewKeyAuthorization.deactivateIndex,
    deactivateLeaves: processDeactivate.finalDeactivateLeaves,
    newPrivateKey: newKeyPrivateKey,
  });
  const commands = [
    { isValid: true, stateIndex: 3, voteOptionIndex: 2, newVoteWeight: 5n },
    { isValid: true, stateIndex: 3, voteOptionIndex: 1, newVoteWeight: 3n },
    { isValid: true, stateIndex: 3, voteOptionIndex: 0, newVoteWeight: 2n },
  ];
  const processMessagesDraft = buildSmallProcessMessagesFixture({
    commands,
    numSignUps: 4n,
    initialVoteLeavesByState,
    initialActiveLeaves: processDeactivate.finalActiveLeaves,
    deactivateRoot: processDeactivateEvaluated.publicFields.newDeactivateRoot,
    // Messages are processed 2 -> 1 -> 0, and each valid command rotates to scalar 500 + i.
    signatureSecretKeys: [501n, 502n, newKeyPrivateKey],
  });
  const processMessagesEvaluated = evaluateNativeProcessMessagesBoundary(processMessagesDraft);
  const processMessages = processMessagesDraft;
  const stateResult = evaluateProcessMessagesStateful(processMessagesDraft).state;
  const transitionContexts = nativeProcessMessageTransitionContexts(stateResult, processMessagesDraft);
  const contextsByStateIndex = new Map();
  for (let index = 0; index < transitionContexts.length; index += 1) {
    const stateIndex = Number(stateResult.transitions[index].derived.stateIndex);
    if (!contextsByStateIndex.has(stateIndex)) {
      contextsByStateIndex.set(stateIndex, transitionContexts[index]);
    }
  }
  const finalStateLeaves = [];
  const finalVotes = [];
  for (let stateIndex = 0; stateIndex < TREE_ARITY; stateIndex += 1) {
    const context = contextsByStateIndex.get(stateIndex);
    finalStateLeaves.push(context?.newStateLeaf ?? Array.from({ length: 10 }, () => 0n));
    finalVotes.push(
      context === undefined
        ? Array.from({ length: TREE_ARITY }, () => 0n)
        : processMessagesDraft.finalVoteLeavesByState[stateIndex].map(BigInt),
    );
  }

  const batchZeroContext = contextsByStateIndex.get(3);
  const tallyDraft = {
    packedVals: (4n << 32n).toString(),
    stateRoot: batchZeroContext.newStateRoot.toString(),
    stateSalt: processMessages.newStateSalt,
    stateLeaf: finalStateLeaves,
    statePathElements: [batchZeroContext.newStateLeafPathElements[1]],
    votes: finalVotes,
    currentResults: Array.from({ length: TREE_ARITY }, () => 0n),
    currentResultsRootSalt: '0',
    newResultsRootSalt: '901',
  };
  const tallyEvaluated = evaluateNativeTallyVotes(tallyDraft);
  const tally = {
    ...tallyDraft,
    stateCommitment: tallyEvaluated.publicFields.stateCommitment,
    currentTallyCommitment: tallyEvaluated.publicFields.currentTallyCommitment,
    newTallyCommitment: tallyEvaluated.publicFields.newTallyCommitment,
    inputHash: tallyEvaluated.publicFields.inputHash,
  };

  return decimalize({
    addNewKey,
    processDeactivate,
    processMessages,
    tally,
    chain: {
      schema: 'zkstark-amaci.full-native-lifecycle-fixture.v1',
      params: {
        stateTreeDepth: 2,
        intStateTreeDepth: 1,
        voteOptionTreeDepth: 1,
        messageBatchSize: 3,
        signupCount: 3,
        newKeyStateIndex: 3,
      },
      flow: ['signup', 'deactivate', 'processDeactivate', 'addNewKey', 'vote', 'processMessages', 'tally'],
      signup: {
        count: 3,
        oldStateIndexes: [0, 1, 2],
        initialStateCommitment: nativeHashFelts(
          [BigInt(processDeactivate.currentStateRoot), 650n],
          'lifecycleInitialStateCommitment',
        ),
      },
      addNewKey: {
        oldStateIndex: addNewKeyAuthorization.stateIndex,
        newStateIndex: 3,
        nullifier: addNewKey.nullifier,
        deactivateRoot: addNewKey.deactivateRoot,
        newStateCommitment: processMessagesEvaluated.publicFields.currentStateCommitment,
      },
      votes: {
        messagesPerProcessBatch: 3,
        processMessageOrder: 'messages are processed from index 2 down to index 0; index 0 is the latest command in this fixture',
        lifecyclePlacement: 'all vote messages are published after addNewKey and before processMessages',
        commands,
        finalVoteLeavesForNewStateIndex: processMessagesDraft.finalVoteLeavesByState[3],
      },
      deactivate: {
        currentDeactivateCommitment: processDeactivateEvaluated.publicFields.currentDeactivateCommitment,
        newDeactivateCommitment: processDeactivateEvaluated.publicFields.newDeactivateCommitment,
        deactivatedStateIndexes: processDeactivate.deactivatedStateIndexes,
        note:
          'This lifecycle fixture uses a stateful deactivate stage input with processOneWitnesses. Its native new deactivate commitment is used as the processMsg deactivate commitment.',
      },
      processMessages: {
        currentStateCommitment: processMessagesEvaluated.publicFields.currentStateCommitment,
        newStateCommitment: processMessagesEvaluated.publicFields.newStateCommitment,
        deactivateCommitment: processMessagesEvaluated.publicFields.deactivateCommitment,
      },
      tally: {
        stateCommitment: tallyEvaluated.publicFields.stateCommitment,
        currentTallyCommitment: tallyEvaluated.publicFields.currentTallyCommitment,
        newTallyCommitment: tallyEvaluated.publicFields.newTallyCommitment,
        newResults: tallyEvaluated.derived.newResults,
      },
      links: {
        deactivateToProcessMessages:
          processDeactivateEvaluated.publicFields.newDeactivateCommitment
            === processMessagesEvaluated.publicFields.deactivateCommitment,
        processMessagesToTallyState:
          processMessagesEvaluated.publicFields.newStateCommitment
            === tallyEvaluated.publicFields.stateCommitment,
      },
    },
  });
}

function emptyStateLeaf() {
  return Array.from({ length: 10 }, () => 0n);
}

function buildTallyBatchInput({
  stateLeaves,
  voteLeavesByState,
  numSignUps,
  batchNum,
  stateSalt,
  currentResults,
  currentResultsRootSalt,
  newResultsRootSalt,
}) {
  const stateLeafHashes = stateLeaves.map((leaf, index) => nativeHash10(leaf, `tallyStateLeaf[${index}]`));
  const batchStart = batchNum * TREE_ARITY;
  const stateSubroots = [];
  for (let i = 0; i < stateLeafHashes.length; i += TREE_ARITY) {
    stateSubroots.push(nativeHash5(stateLeafHashes.slice(i, i + TREE_ARITY), `tallyStateSubroot[${i}]`));
  }
  return {
    packedVals: ((BigInt(numSignUps) << 32n) + BigInt(batchNum)).toString(),
    stateRoot: nativeHash5(stateSubroots, 'tallyStateRoot').toString(),
    stateSalt: BigInt(stateSalt).toString(),
    stateLeaf: stateLeaves.slice(batchStart, batchStart + TREE_ARITY),
    statePathElements: [stateSubroots.filter((_, index) => index !== batchNum)],
    votes: voteLeavesByState.slice(batchStart, batchStart + TREE_ARITY),
    currentResults,
    currentResultsRootSalt: BigInt(currentResultsRootSalt).toString(),
    newResultsRootSalt: BigInt(newResultsRootSalt).toString(),
  };
}

export function buildFiveSignupSimplifiedRoundFixture() {
  const signupStateIndexes = [0, 1, 2, 3, 4];
  const oldPrivateKeys = {
    0: 101n,
    1: 102n,
    2: 103n,
    3: 104n,
    4: 105n,
  };
  const effectiveNumSignUps = 6n;
  const newKeyStateIndex = 5;
  const newKeyPrivateKey = 13n;
  const initialVoteLeavesByState = Array.from({ length: 25 }, () =>
    Array.from({ length: TREE_ARITY }, () => 0n),
  );
  const processDeactivate = buildSmallProcessDeactivateFixture({
    stateIndexes: [3, 4],
    signupStateIndexes,
    privateKeysByState: oldPrivateKeys,
  });
  const processDeactivateEvaluated = evaluateNativeProcessDeactivateMessagesBoundary(processDeactivate);
  const addNewKeyAuthorization = processDeactivate.deactivateAuthorizations.find(
    (authorization) => authorization.stateIndex === 4,
  );
  const addNewKey = buildSmallAddNewKeyFixture({
    coordPubKey: processDeactivate.coordPubKey,
    oldPrivateKey: addNewKeyAuthorization.oldPrivateKey,
    pollId: processDeactivate.expectedPollId,
    c1: addNewKeyAuthorization.c1,
    c2: addNewKeyAuthorization.c2,
    deactivateIndex: addNewKeyAuthorization.deactivateIndex,
    deactivateLeaves: processDeactivate.finalDeactivateLeaves,
    newPrivateKey: newKeyPrivateKey,
  });

  const stateLeavesAfterAddNewKey = Array.from({ length: 25 }, emptyStateLeaf);
  for (const [stateIndex, stateLeaf] of Object.entries(processDeactivate.signupStateEntries)) {
    stateLeavesAfterAddNewKey[Number(stateIndex)] = stateLeaf.map(BigInt);
  }
  stateLeavesAfterAddNewKey[newKeyStateIndex] = [
    ...addNewKey.newPubKey.map(BigInt),
    2005n,
    0n,
    0n,
    ...addNewKey.d1.map(BigInt),
    ...addNewKey.d2.map(BigInt),
    0n,
  ];

  const processMessages0 = buildSmallProcessMessagesFixture({
    commands: [
      { isValid: true, stateIndex: 0, voteOptionIndex: 0, newVoteWeight: 1n },
      { isValid: true, stateIndex: 0, voteOptionIndex: 4, newVoteWeight: 5n },
      { isValid: false, stateIndex: 3, voteOptionIndex: 1, newVoteWeight: 1n },
    ],
    numSignUps: effectiveNumSignUps,
    initialVoteLeavesByState,
    initialStateLeaves: stateLeavesAfterAddNewKey,
    initialActiveLeaves: processDeactivate.finalActiveLeaves,
    deactivateRoot: processDeactivateEvaluated.publicFields.newDeactivateRoot,
    currentStateSalt: 801n,
    newStateSalt: 802n,
    signatureSecretKeys: [501n, oldPrivateKeys[0], oldPrivateKeys[3]],
  });
  const processMessages0Evaluated = evaluateNativeProcessMessagesBoundary(processMessages0);

  const processMessages1 = buildSmallProcessMessagesFixture({
    commands: [
      { isValid: false, stateIndex: 4, voteOptionIndex: 2, newVoteWeight: 2n },
      { isValid: true, stateIndex: newKeyStateIndex, voteOptionIndex: 4, newVoteWeight: 5n },
      { isValid: false, stateIndex: 24, voteOptionIndex: 0, newVoteWeight: 0n },
    ],
    numSignUps: effectiveNumSignUps,
    initialVoteLeavesByState: processMessages0.finalVoteLeavesByState,
    initialStateLeaves: processMessages0.finalStateLeaves,
    initialActiveLeaves: processDeactivate.finalActiveLeaves,
    deactivateRoot: processDeactivateEvaluated.publicFields.newDeactivateRoot,
    batchStartHash: processMessages0Evaluated.publicFields.batchEndHash,
    currentStateSalt: processMessages0.newStateSalt,
    newStateSalt: 803n,
    signatureSecretKeys: [oldPrivateKeys[4], newKeyPrivateKey, undefined],
  });
  const processMessages1Evaluated = evaluateNativeProcessMessagesBoundary(processMessages1);

  const finalStateLeaves = processMessages1.finalStateLeaves.map((leaf) => leaf.map(BigInt));
  const finalVotes = processMessages1.finalVoteLeavesByState.map((row) => row.map(BigInt));
  const tally0Draft = buildTallyBatchInput({
    stateLeaves: finalStateLeaves,
    voteLeavesByState: finalVotes,
    numSignUps: effectiveNumSignUps,
    batchNum: 0,
    stateSalt: processMessages1.newStateSalt,
    currentResults: Array.from({ length: TREE_ARITY }, () => 0n),
    currentResultsRootSalt: 0n,
    newResultsRootSalt: 901n,
  });
  const tally0Evaluated = evaluateNativeTallyVotes(tally0Draft);
  const tally0 = {
    ...tally0Draft,
    stateCommitment: tally0Evaluated.publicFields.stateCommitment,
    currentTallyCommitment: tally0Evaluated.publicFields.currentTallyCommitment,
    newTallyCommitment: tally0Evaluated.publicFields.newTallyCommitment,
    inputHash: tally0Evaluated.publicFields.inputHash,
  };

  const tally1Draft = buildTallyBatchInput({
    stateLeaves: finalStateLeaves,
    voteLeavesByState: finalVotes,
    numSignUps: effectiveNumSignUps,
    batchNum: 1,
    stateSalt: processMessages1.newStateSalt,
    currentResults: tally0Evaluated.derived.newResults,
    currentResultsRootSalt: tally0.newResultsRootSalt,
    newResultsRootSalt: 902n,
  });
  const tally1Evaluated = evaluateNativeTallyVotes(tally1Draft);
  const tally1 = {
    ...tally1Draft,
    stateCommitment: tally1Evaluated.publicFields.stateCommitment,
    currentTallyCommitment: tally1Evaluated.publicFields.currentTallyCommitment,
    newTallyCommitment: tally1Evaluated.publicFields.newTallyCommitment,
    inputHash: tally1Evaluated.publicFields.inputHash,
  };

  const rawResults = Array.from({ length: TREE_ARITY }, (_, optionIndex) =>
    finalVotes.reduce((sum, row) => sum + row[optionIndex], 0n),
  );

  return decimalize({
    addNewKey,
    processDeactivate,
    processMessages: [processMessages0, processMessages1],
    tally: [tally0, tally1],
    chain: {
      schema: 'zkstark-amaci.five-signup-simplified-round-fixture.v1',
      params: {
        stateTreeDepth: 2,
        intStateTreeDepth: 1,
        voteOptionTreeDepth: 1,
        messageBatchSize: 3,
        signupCount: 5,
        effectiveNumSignUps,
        deactivateMessageCount: 2,
        addNewKeyCount: 1,
        publishedVoteMessageCount: 5,
        processMessageBatchSlots: 6,
        invalidPaddingVoteSlots: 1,
        processMessageBatches: 2,
        tallyBatches: 2,
        newKeyStateIndex,
      },
      flow: [
        'signup',
        'deactivate',
        'processDeactivate',
        'addNewKey',
        'vote',
        'processMessages[0]',
        'processMessages[1]',
        'tally[0]',
        'tally[1]',
      ],
      signup: {
        count: 5,
        oldStateIndexes: signupStateIndexes,
        initialStateCommitment: nativeHashFelts(
          [BigInt(processDeactivate.currentStateRoot), 650n],
          'fiveSignupInitialStateCommitment',
        ),
      },
      deactivate: {
        deactivatedStateIndexes: [3, 4],
        processedDeactivateMessageCount: 2,
        currentDeactivateCommitment: processDeactivateEvaluated.publicFields.currentDeactivateCommitment,
        newDeactivateCommitment: processDeactivateEvaluated.publicFields.newDeactivateCommitment,
      },
      addNewKey: {
        oldStateIndex: 4,
        newStateIndex: newKeyStateIndex,
        nullifier: addNewKey.nullifier,
        deactivateRoot: addNewKey.deactivateRoot,
        newStateCommitment: processMessages0Evaluated.publicFields.currentStateCommitment,
      },
      votes: {
        publishedCommands: [
          { stateIndex: 0, voteOptionIndex: 0, newVoteWeight: 1n, expectedEffect: 'valid' },
          { stateIndex: 0, voteOptionIndex: 4, newVoteWeight: 5n, expectedEffect: 'valid' },
          { stateIndex: 3, voteOptionIndex: 1, newVoteWeight: 1n, expectedEffect: 'invalid-old-key' },
          { stateIndex: 4, voteOptionIndex: 2, newVoteWeight: 2n, expectedEffect: 'invalid-old-key' },
          { stateIndex: 5, voteOptionIndex: 4, newVoteWeight: 5n, expectedEffect: 'valid-new-key' },
        ],
        expectedRawResults: rawResults,
      },
      processMessages: [
        {
          currentStateCommitment: processMessages0Evaluated.publicFields.currentStateCommitment,
          newStateCommitment: processMessages0Evaluated.publicFields.newStateCommitment,
          batchStartHash: processMessages0Evaluated.publicFields.batchStartHash,
          batchEndHash: processMessages0Evaluated.publicFields.batchEndHash,
          deactivateCommitment: processMessages0Evaluated.publicFields.deactivateCommitment,
        },
        {
          currentStateCommitment: processMessages1Evaluated.publicFields.currentStateCommitment,
          newStateCommitment: processMessages1Evaluated.publicFields.newStateCommitment,
          batchStartHash: processMessages1Evaluated.publicFields.batchStartHash,
          batchEndHash: processMessages1Evaluated.publicFields.batchEndHash,
          deactivateCommitment: processMessages1Evaluated.publicFields.deactivateCommitment,
        },
      ],
      tally: [
        {
          batchNum: 0,
          stateCommitment: tally0Evaluated.publicFields.stateCommitment,
          currentTallyCommitment: tally0Evaluated.publicFields.currentTallyCommitment,
          newTallyCommitment: tally0Evaluated.publicFields.newTallyCommitment,
          newResults: tally0Evaluated.derived.newResults,
        },
        {
          batchNum: 1,
          stateCommitment: tally1Evaluated.publicFields.stateCommitment,
          currentTallyCommitment: tally1Evaluated.publicFields.currentTallyCommitment,
          newTallyCommitment: tally1Evaluated.publicFields.newTallyCommitment,
          newResults: tally1Evaluated.derived.newResults,
        },
      ],
      links: {
        processDeactivateToAddNewKey:
          processDeactivateEvaluated.publicFields.newDeactivateRoot
            === BigInt(addNewKey.deactivateRoot),
        deactivateToProcessMessages0:
          processDeactivateEvaluated.publicFields.newDeactivateCommitment
            === processMessages0Evaluated.publicFields.deactivateCommitment,
        addNewKeyToProcessMessages0:
          processMessages0Evaluated.publicFields.currentStateCommitment
            === BigInt(processMessages0.currentStateCommitment),
        processMessages0To1:
          processMessages0Evaluated.publicFields.newStateCommitment
            === processMessages1Evaluated.publicFields.currentStateCommitment,
        messageHashChain0To1:
          processMessages0Evaluated.publicFields.batchEndHash
            === processMessages1Evaluated.publicFields.batchStartHash,
        processMessages1ToTally:
          processMessages1Evaluated.publicFields.newStateCommitment
            === tally0Evaluated.publicFields.stateCommitment
            && tally0Evaluated.publicFields.stateCommitment
            === tally1Evaluated.publicFields.stateCommitment,
        tally0To1:
          tally0Evaluated.publicFields.newTallyCommitment
            === tally1Evaluated.publicFields.currentTallyCommitment,
      },
    },
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
