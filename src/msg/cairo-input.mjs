import { bigintToHex, decimalize, splitU256ToU128 } from '../encoding.mjs';
import {
  NATIVE_PUBLIC_OUTPUT_VERSION,
  PROCESS_MESSAGE_COORD_KEY_NATIVE_CIRCUIT_ID,
  PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
  PROCESS_MESSAGE_DECRYPT_NATIVE_CIRCUIT_ID,
  PROCESS_MESSAGE_ECDH_NATIVE_CIRCUIT_ID,
  PROCESS_MESSAGE_NATIVE_COORD_KEY_BINDING_DOMAIN,
  PROCESS_MESSAGE_NATIVE_COMMAND_AUTH_DOMAIN,
  PROCESS_MESSAGE_NATIVE_COMMAND_PLAINTEXT_DOMAIN,
  PROCESS_MESSAGE_NATIVE_DECRYPT_BINDING_DOMAIN,
  PROCESS_MESSAGE_NATIVE_SHARED_KEY_DOMAIN,
  PROCESS_MESSAGE_SIGNATURE_NATIVE_CIRCUIT_ID,
  PROCESS_MESSAGE_STEP_CORE_NATIVE_CIRCUIT_ID,
  PUBLIC_OUTPUT_MAGIC,
  SMALL_PROCESS_MESSAGES_PARAMS,
  STARKNET_POSEIDON_HASH_SCHEME,
} from '../constants.mjs';
import { poseidonManyFelts } from '../integrity/hashes.mjs';
import { toStarkFelt } from '../tally/native-tally-votes.mjs';
import { evaluateProcessMessagesStateful } from './process-messages.mjs';
import { nativeProcessMessageTransitionContexts } from './native-process-roots.mjs';

function splitObject(value, label) {
  const { low, high } = splitU256ToU128(value, label);
  return {
    low: low.toString(),
    high: high.toString(),
  };
}

function feltObject(value) {
  return value.toString();
}

function nativeFelt(value, label) {
  return toStarkFelt(value, label);
}

function nativeHashFelts(values, label) {
  return poseidonManyFelts(values.map((value, index) => nativeFelt(value, `${label}[${index}]`)));
}

function nativeHashU256(value, label) {
  return nativeHashFelts([value], label);
}

function nativeHashPoint(values, label) {
  if (!Array.isArray(values) || values.length !== 2) {
    throw new Error(`${label} must contain two values`);
  }
  return nativeHashFelts(values, label);
}

function nativeCoordPrivKeyHash(coordPrivKey) {
  return nativeHashFelts([coordPrivKey, PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN], 'coordPrivKey');
}

function nativeCoordKeyBindingHash(coordPubKeyHash, coordPrivKeyHash) {
  return nativeHashFelts(
    [PROCESS_MESSAGE_NATIVE_COORD_KEY_BINDING_DOMAIN, coordPubKeyHash, coordPrivKeyHash],
    'coordKeyBinding',
  );
}

function nativePackedCommandHash(packedCommand) {
  if (!Array.isArray(packedCommand) || packedCommand.length !== 3) {
    throw new Error('packedCommand must contain three values');
  }
  return nativeHashFelts(packedCommand, 'packedCommand');
}

function nativeCommandAuthHash(pubKeyHash, r8Hash, packedCommandHash, cmdSigSHash, cmdSalt, isSignatureValid) {
  return nativeHashFelts(
    [
      PROCESS_MESSAGE_NATIVE_COMMAND_AUTH_DOMAIN,
      pubKeyHash,
      r8Hash,
      packedCommandHash,
      cmdSigSHash,
      cmdSalt,
      isSignatureValid,
    ],
    'commandAuth',
  );
}

function nativeCommandPlaintextBindingHash(
  nextMessageHash,
  sharedKeyHash,
  packedCommandHash,
  signaturePubKeyHash,
  signatureR8Hash,
  cmdSigSHash,
  commandAuthHash,
) {
  return nativeHashFelts(
    [
      PROCESS_MESSAGE_NATIVE_COMMAND_PLAINTEXT_DOMAIN,
      nextMessageHash,
      sharedKeyHash,
      packedCommandHash,
      signaturePubKeyHash,
      signatureR8Hash,
      cmdSigSHash,
      commandAuthHash,
    ],
    'commandPlaintextBinding',
  );
}

function nativeDecryptBindingHash(coordPrivKeyHash, c1Hash, c2Hash, decryptIsOdd) {
  return nativeHashFelts(
    [PROCESS_MESSAGE_NATIVE_DECRYPT_BINDING_DOMAIN, coordPrivKeyHash, c1Hash, c2Hash, decryptIsOdd],
    'decryptBinding',
  );
}

function nativeSharedKeyBindingHash(coordPrivKeyHash, encPubKeyHash, sharedKeyHash) {
  return nativeHashFelts(
    [PROCESS_MESSAGE_NATIVE_SHARED_KEY_DOMAIN, coordPrivKeyHash, encPubKeyHash, sharedKeyHash],
    'sharedKeyBinding',
  );
}

function nativeMessageHash(message, encPubKey, previousHash) {
  return nativeHashFelts([...message, encPubKey[0], encPubKey[1], previousHash], 'messageHash');
}

function nativeMessageHashOrEmpty(message, encPubKey, previousHash) {
  return nativeFelt(encPubKey[0], 'encPubKey[0]') === 0n
    ? nativeFelt(previousHash, 'previousHash')
    : nativeMessageHash(message, encPubKey, previousHash);
}

function nativeMessageHashChain(messages, encPubKeys, batchStartHash) {
  const chain = [nativeFelt(batchStartHash, 'batchStartHash')];
  for (let index = 0; index < messages.length; index += 1) {
    chain.push(nativeMessageHashOrEmpty(messages[index], encPubKeys[index], chain[index]));
  }
  return chain;
}

function nativeCommitment(root, salt, label) {
  return nativeHashFelts([root, salt], label);
}

function nativeProcessMessagePublicOutput(circuitId, fields, params, fieldLabels) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'hash_scheme',
    'state_tree_depth',
    'vote_option_tree_depth',
    'message_batch_size',
    ...fieldLabels,
  ];
  const felts = [
    PUBLIC_OUTPUT_MAGIC,
    NATIVE_PUBLIC_OUTPUT_VERSION,
    circuitId,
    STARKNET_POSEIDON_HASH_SCHEME,
    BigInt(params.stateTreeDepth),
    BigInt(params.voteOptionTreeDepth),
    BigInt(params.messageBatchSize),
    ...fieldLabels.map((label) => fields[label]),
  ];
  return {
    labels,
    felts,
    decimalFelts: felts.map(decimalize),
  };
}

function splitVector2(values, label) {
  if (!Array.isArray(values) || values.length !== 2) {
    throw new Error(`${label} must contain two values`);
  }
  return {
    v0: splitObject(values[0], `${label}[0]`),
    v1: splitObject(values[1], `${label}[1]`),
  };
}

function splitVector3(values, label) {
  if (!Array.isArray(values) || values.length !== 3) {
    throw new Error(`${label} must contain three values`);
  }
  return {
    v0: splitObject(values[0], `${label}[0]`),
    v1: splitObject(values[1], `${label}[1]`),
    v2: splitObject(values[2], `${label}[2]`),
  };
}

function splitVector4(values, label) {
  if (!Array.isArray(values) || values.length !== 4) {
    throw new Error(`${label} must contain four values`);
  }
  return {
    v0: splitObject(values[0], `${label}[0]`),
    v1: splitObject(values[1], `${label}[1]`),
    v2: splitObject(values[2], `${label}[2]`),
    v3: splitObject(values[3], `${label}[3]`),
  };
}

function splitVector7(values, label) {
  if (!Array.isArray(values) || values.length !== 7) {
    throw new Error(`${label} must contain seven values`);
  }
  return {
    v0: splitObject(values[0], `${label}[0]`),
    v1: splitObject(values[1], `${label}[1]`),
    v2: splitObject(values[2], `${label}[2]`),
    v3: splitObject(values[3], `${label}[3]`),
    v4: splitObject(values[4], `${label}[4]`),
    v5: splitObject(values[5], `${label}[5]`),
    v6: splitObject(values[6], `${label}[6]`),
  };
}

function splitVector10(values, label) {
  if (!Array.isArray(values) || values.length !== 10) {
    throw new Error(`${label} must contain ten values`);
  }
  return {
    v0: splitObject(values[0], `${label}[0]`),
    v1: splitObject(values[1], `${label}[1]`),
    v2: splitObject(values[2], `${label}[2]`),
    v3: splitObject(values[3], `${label}[3]`),
    v4: splitObject(values[4], `${label}[4]`),
    v5: splitObject(values[5], `${label}[5]`),
    v6: splitObject(values[6], `${label}[6]`),
    v7: splitObject(values[7], `${label}[7]`),
    v8: splitObject(values[8], `${label}[8]`),
    v9: splitObject(values[9], `${label}[9]`),
  };
}

function buildProcessOneStateTransitionWitnessFromEvaluation(result) {
  const { input } = result;
  return {
    is_quadratic_cost: splitObject(input.isQuadraticCost, 'isQuadraticCost'),
    num_signups: splitObject(input.numSignUps, 'numSignUps'),
    max_vote_options: splitObject(input.maxVoteOptions, 'maxVoteOptions'),
    expected_poll_id: splitObject(input.expectedPollId, 'expectedPollId'),
    is_signature_valid: splitObject(input.isSignatureValid, 'isSignatureValid'),
    is_decryption_active: splitObject(input.isDecryptionActive, 'isDecryptionActive'),
    msg: splitVector10(input.msg, 'msg'),
    shared_key: splitVector2(input.sharedKey, 'sharedKey'),
    decrypted_command: splitVector7(input.decryptedCommand, 'decryptedCommand'),
    packed_command: splitVector3(input.packedCommand, 'packedCommand'),
    cmd_salt: splitObject(input.cmdSalt, 'cmdSalt'),
    cmd_sig_r8: splitVector2(input.cmdSigR8, 'cmdSigR8'),
    cmd_sig_s: splitObject(input.cmdSigS, 'cmdSigS'),
    current_state_root: splitObject(input.currentStateRoot, 'currentStateRoot'),
    active_state_root: splitObject(input.activeStateRoot, 'activeStateRoot'),
    state_leaf: splitVector10(input.stateLeaf, 'stateLeaf'),
    state_decrypted_point: splitVector2(result.derived.stateDecrypt.decryptedPoint, 'stateDecryptedPoint'),
    state_leaf_path_0: splitVector4(input.stateLeafPathElements[0], 'stateLeafPathElements[0]'),
    state_leaf_path_1: splitVector4(input.stateLeafPathElements[1], 'stateLeafPathElements[1]'),
    active_state_leaf: splitObject(input.activeStateLeaf, 'activeStateLeaf'),
    active_state_leaf_path_0: splitVector4(
      input.activeStateLeafPathElements[0],
      'activeStateLeafPathElements[0]',
    ),
    active_state_leaf_path_1: splitVector4(
      input.activeStateLeafPathElements[1],
      'activeStateLeafPathElements[1]',
    ),
    current_vote_weight: splitObject(input.currentVoteWeight, 'currentVoteWeight'),
    current_vote_weight_path: splitVector4(
      input.currentVoteWeightsPathElements[0],
      'currentVoteWeightsPathElements[0]',
    ),
    is_valid: splitObject(input.isValid, 'isValid'),
    cmd_state_index: splitObject(input.cmdStateIndex, 'cmdStateIndex'),
    cmd_vote_option_index: splitObject(input.cmdVoteOptionIndex, 'cmdVoteOptionIndex'),
    cmd_new_vote_weight: splitObject(input.cmdNewVoteWeight, 'cmdNewVoteWeight'),
    cmd_nonce: splitObject(input.cmdNonce, 'cmdNonce'),
    cmd_poll_id: splitObject(input.cmdPollId, 'cmdPollId'),
    cmd_new_pub_key: splitVector2(input.cmdNewPubKey, 'cmdNewPubKey'),
    new_balance: splitObject(input.newBalance, 'newBalance'),
    new_sl_nonce: splitObject(input.newSlNonce, 'newSlNonce'),
  };
}

function assertMessageIndex(messageIndex) {
  const maxIndex = SMALL_PROCESS_MESSAGES_PARAMS.messageBatchSize - 1;
  if (!Number.isInteger(messageIndex) || messageIndex < 0 || messageIndex > maxIndex) {
    throw new Error(`messageIndex must be an integer in [0, ${maxIndex}]`);
  }
}

function isEmptyMessage(rawInput, messageIndex) {
  return BigInt(rawInput.encPubKeys[messageIndex][0]) === 0n;
}

function processMessageStepLinkFields(rawInput, messageIndex, result) {
  const transition = result.state.transitions[messageIndex];
  return {
    cmdSigS: transition.input.cmdSigS,
    isSignatureValid: transition.input.isSignatureValid,
  };
}

export function buildNativeCairoProcessMessageCoordKeyInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const coordPubKeyHash = nativeHashPoint(rawInput.coordPubKey, 'coordPubKey');
  const coordPrivKeyHash = nativeCoordPrivKeyHash(rawInput.coordPrivKey);
  const publicFields = {
    coord_pub_key_hash: coordPubKeyHash,
    coord_priv_key_hash: coordPrivKeyHash,
    coord_key_binding_hash: nativeCoordKeyBindingHash(coordPubKeyHash, coordPrivKeyHash),
  };
  const fields = {
    coord_pub_key_hash: feltObject(publicFields.coord_pub_key_hash),
    coord_priv_key_hash: feltObject(publicFields.coord_priv_key_hash),
    coord_key_binding_hash: feltObject(publicFields.coord_key_binding_hash),
  };
  const publicOutput = nativeProcessMessagePublicOutput(
    PROCESS_MESSAGE_COORD_KEY_NATIVE_CIRCUIT_ID,
    publicFields,
    result.params,
    ['coord_pub_key_hash', 'coord_priv_key_hash', 'coord_key_binding_hash'],
  );

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        coord_priv_key: splitObject(rawInput.coordPrivKey, 'coordPrivKey'),
        coord_pub_key: splitVector2(rawInput.coordPubKey, 'coordPubKey'),
      },
    },
    full_witness: {
      processMessages: rawInput,
      nativeCoordKeyBinding: true,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessMessageEcdhInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const coordPrivKeyHash = nativeCoordPrivKeyHash(rawInput.coordPrivKey);
  const encPubKeyHash = nativeHashPoint(rawInput.encPubKeys[messageIndex], 'encPubKey');
  const sharedKeyHash = nativeHashPoint(transition.input.sharedKey, 'sharedKey');
  const publicFields = {
    message_index: BigInt(messageIndex),
    coord_priv_key_hash: coordPrivKeyHash,
    enc_pub_key_hash: encPubKeyHash,
    shared_key_hash: sharedKeyHash,
    shared_key_binding_hash: nativeSharedKeyBindingHash(coordPrivKeyHash, encPubKeyHash, sharedKeyHash),
  };
  const fields = {
    message_index: feltObject(publicFields.message_index),
    coord_priv_key_hash: feltObject(publicFields.coord_priv_key_hash),
    enc_pub_key_hash: feltObject(publicFields.enc_pub_key_hash),
    shared_key_hash: feltObject(publicFields.shared_key_hash),
    shared_key_binding_hash: feltObject(publicFields.shared_key_binding_hash),
  };
  const publicOutput = nativeProcessMessagePublicOutput(
    PROCESS_MESSAGE_ECDH_NATIVE_CIRCUIT_ID,
    publicFields,
    result.params,
    [
      'message_index',
      'coord_priv_key_hash',
      'enc_pub_key_hash',
      'shared_key_hash',
      'shared_key_binding_hash',
    ],
  );

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        coord_priv_key: splitObject(rawInput.coordPrivKey, 'coordPrivKey'),
        enc_pub_key: splitVector2(rawInput.encPubKeys[messageIndex], 'encPubKey'),
        shared_key: splitVector2(transition.input.sharedKey, 'sharedKey'),
      },
    },
    full_witness: {
      processMessages: rawInput,
      messageIndex,
      nativeSharedKey: true,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessMessageDecryptInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const c1 = transition.input.stateLeaf.slice(5, 7);
  const c2 = transition.input.stateLeaf.slice(7, 9);
  const decryptIsOdd = 1n - transition.input.isDecryptionActive;
  const coordPrivKeyHash = nativeCoordPrivKeyHash(rawInput.coordPrivKey);
  const c1Hash = nativeHashPoint(c1, 'stateCiphertextC1');
  const c2Hash = nativeHashPoint(c2, 'stateCiphertextC2');
  const publicFields = {
    message_index: BigInt(messageIndex),
    coord_priv_key_hash: coordPrivKeyHash,
    c1_hash: c1Hash,
    c2_hash: c2Hash,
    decrypt_is_odd: decryptIsOdd,
    decrypt_binding_hash: nativeDecryptBindingHash(coordPrivKeyHash, c1Hash, c2Hash, decryptIsOdd),
  };
  const fields = {
    message_index: feltObject(publicFields.message_index),
    coord_priv_key_hash: feltObject(publicFields.coord_priv_key_hash),
    c1_hash: feltObject(publicFields.c1_hash),
    c2_hash: feltObject(publicFields.c2_hash),
    decrypt_is_odd: feltObject(publicFields.decrypt_is_odd),
    decrypt_binding_hash: feltObject(publicFields.decrypt_binding_hash),
  };
  const publicOutput = nativeProcessMessagePublicOutput(
    PROCESS_MESSAGE_DECRYPT_NATIVE_CIRCUIT_ID,
    publicFields,
    result.params,
    [
      'message_index',
      'coord_priv_key_hash',
      'c1_hash',
      'c2_hash',
      'decrypt_is_odd',
      'decrypt_binding_hash',
    ],
  );

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        coord_priv_key: splitObject(rawInput.coordPrivKey, 'coordPrivKey'),
        c1: splitVector2(c1, 'stateCiphertextC1'),
        c2: splitVector2(c2, 'stateCiphertextC2'),
        decrypted_point: splitVector2(transition.derived.stateDecrypt.decryptedPoint, 'stateDecryptedPoint'),
      },
    },
    full_witness: {
      processMessages: rawInput,
      messageIndex,
      nativeDecryptBinding: true,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessMessageSignatureInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const pubKey = [transition.input.stateLeaf[0], transition.input.stateLeaf[1]];
  const pubKeyHash = nativeHashPoint(pubKey, 'pubKey');
  const r8Hash = nativeHashPoint(transition.input.cmdSigR8, 'r8');
  const packedCommandHash = nativePackedCommandHash(transition.input.packedCommand);
  const cmdSigSHash = nativeHashU256(transition.input.cmdSigS, 'cmdSigS');
  const publicFields = {
    message_index: BigInt(messageIndex),
    pub_key_hash: pubKeyHash,
    r8_hash: r8Hash,
    packed_command_hash: packedCommandHash,
    cmd_sig_s_hash: cmdSigSHash,
    command_auth_hash: nativeCommandAuthHash(
      pubKeyHash,
      r8Hash,
      packedCommandHash,
      cmdSigSHash,
      transition.input.cmdSalt,
      transition.input.isSignatureValid,
    ),
    is_signature_valid: transition.input.isSignatureValid,
  };
  const fields = {
    message_index: feltObject(publicFields.message_index),
    pub_key_hash: feltObject(publicFields.pub_key_hash),
    r8_hash: feltObject(publicFields.r8_hash),
    packed_command_hash: feltObject(publicFields.packed_command_hash),
    cmd_sig_s_hash: feltObject(publicFields.cmd_sig_s_hash),
    command_auth_hash: feltObject(publicFields.command_auth_hash),
    is_signature_valid: feltObject(publicFields.is_signature_valid),
  };
  const publicOutput = nativeProcessMessagePublicOutput(
    PROCESS_MESSAGE_SIGNATURE_NATIVE_CIRCUIT_ID,
    publicFields,
    result.params,
    [
      'message_index',
      'pub_key_hash',
      'r8_hash',
      'packed_command_hash',
      'cmd_sig_s_hash',
      'command_auth_hash',
      'is_signature_valid',
    ],
  );

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        pub_key: splitVector2(pubKey, 'pubKey'),
        r8: splitVector2(transition.input.cmdSigR8, 'r8'),
        s: splitObject(transition.input.cmdSigS, 's'),
        packed_command: splitVector3(transition.input.packedCommand, 'packedCommand'),
        cmd_salt: splitObject(transition.input.cmdSalt, 'cmdSalt'),
      },
    },
    full_witness: {
      processMessages: rawInput,
      messageIndex,
      nativeAuth: true,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessMessageStepCoreInput(rawInput, messageIndex, evaluated) {
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const linkFields = processMessageStepLinkFields(rawInput, messageIndex, result);
  const nativeMsgChain = nativeMessageHashChain(rawInput.msgs, rawInput.encPubKeys, rawInput.batchStartHash);
  const nativeContext = nativeProcessMessageTransitionContexts(result.state, rawInput)[messageIndex];
  const processOneWitness = buildProcessOneStateTransitionWitnessFromEvaluation(transition);
  processOneWitness.state_leaf_path_0 = splitVector4(
    nativeContext.stateLeafPathElements[0],
    'nativeStateLeafPathElements[0]',
  );
  processOneWitness.state_leaf_path_1 = splitVector4(
    nativeContext.stateLeafPathElements[1],
    'nativeStateLeafPathElements[1]',
  );
  processOneWitness.current_vote_weight_path = splitVector4(
    nativeContext.currentVotePathElements[0],
    'nativeCurrentVoteWeightPath',
  );
  const signaturePubKeyHash = nativeHashPoint(
    [transition.input.stateLeaf[0], transition.input.stateLeaf[1]],
    'signaturePubKey',
  );
  const signatureR8Hash = nativeHashPoint(transition.input.cmdSigR8, 'signatureR8');
  const packedCommandHash = nativePackedCommandHash(transition.input.packedCommand);
  const cmdSigSHash = nativeHashU256(linkFields.cmdSigS, 'cmdSigS');
  const encPubKeyHash = nativeHashPoint(rawInput.encPubKeys[messageIndex], 'encPubKey');
  const sharedKeyHash = nativeHashPoint(transition.input.sharedKey, 'sharedKey');
  const stateCiphertextC1Hash = nativeHashPoint(
    transition.input.stateLeaf.slice(5, 7),
    'stateCiphertextC1',
  );
  const stateCiphertextC2Hash = nativeHashPoint(
    transition.input.stateLeaf.slice(7, 9),
    'stateCiphertextC2',
  );
  const stateDecryptIsOdd = 1n - transition.input.isDecryptionActive;
  const nextMessageHash = nativeMsgChain[messageIndex + 1];
  const commandAuthHash = nativeCommandAuthHash(
    signaturePubKeyHash,
    signatureR8Hash,
    packedCommandHash,
    cmdSigSHash,
    transition.input.cmdSalt,
    linkFields.isSignatureValid,
  );
  const publicFields = {
    message_index: BigInt(messageIndex),
    packed_vals_hash: nativeFelt(result.publicFields.packedVals, 'packedVals'),
    coord_priv_key_hash: nativeCoordPrivKeyHash(rawInput.coordPrivKey),
    previous_message_hash: nativeMsgChain[messageIndex],
    next_message_hash: nextMessageHash,
    current_state_root_hash: nativeContext.currentStateRoot,
    new_state_root_hash: nativeContext.newStateRoot,
    current_state_commitment_hash: nativeCommitment(
      nativeContext.currentStateRoot,
      rawInput.currentStateSalt,
      'currentStateCommitment',
    ),
    new_state_commitment_hash: nativeCommitment(
      nativeContext.newStateRoot,
      rawInput.newStateSalt,
      'newStateCommitment',
    ),
    active_state_root_hash: nativeContext.activeStateRoot,
    expected_poll_id: result.publicFields.expectedPollId,
    enc_pub_key_hash: encPubKeyHash,
    shared_key_hash: sharedKeyHash,
    shared_key_binding_hash: nativeSharedKeyBindingHash(
      nativeCoordPrivKeyHash(rawInput.coordPrivKey),
      encPubKeyHash,
      sharedKeyHash,
    ),
    state_ciphertext_c1_hash: stateCiphertextC1Hash,
    state_ciphertext_c2_hash: stateCiphertextC2Hash,
    state_decrypt_is_odd: stateDecryptIsOdd,
    state_decrypt_binding_hash: nativeDecryptBindingHash(
      nativeCoordPrivKeyHash(rawInput.coordPrivKey),
      stateCiphertextC1Hash,
      stateCiphertextC2Hash,
      stateDecryptIsOdd,
    ),
    signature_pub_key_hash: signaturePubKeyHash,
    signature_r8_hash: signatureR8Hash,
    packed_command_hash: packedCommandHash,
    cmd_sig_s_hash: cmdSigSHash,
    command_auth_hash: commandAuthHash,
    command_plaintext_binding_hash: nativeCommandPlaintextBindingHash(
      nextMessageHash,
      sharedKeyHash,
      packedCommandHash,
      signaturePubKeyHash,
      signatureR8Hash,
      cmdSigSHash,
      commandAuthHash,
    ),
    is_signature_valid: linkFields.isSignatureValid,
  };
  const fields = Object.fromEntries(
    Object.entries(publicFields).map(([key, value]) => [key, feltObject(value)]),
  );
  const fieldLabels = [
    'message_index',
    'packed_vals_hash',
    'coord_priv_key_hash',
    'previous_message_hash',
    'next_message_hash',
    'current_state_root_hash',
    'new_state_root_hash',
    'current_state_commitment_hash',
    'new_state_commitment_hash',
    'active_state_root_hash',
    'expected_poll_id',
    'enc_pub_key_hash',
    'shared_key_hash',
    'shared_key_binding_hash',
    'state_ciphertext_c1_hash',
    'state_ciphertext_c2_hash',
    'state_decrypt_is_odd',
    'state_decrypt_binding_hash',
    'signature_pub_key_hash',
    'signature_r8_hash',
    'packed_command_hash',
    'cmd_sig_s_hash',
    'command_auth_hash',
    'command_plaintext_binding_hash',
    'is_signature_valid',
  ];
  const publicOutput = nativeProcessMessagePublicOutput(
    PROCESS_MESSAGE_STEP_CORE_NATIVE_CIRCUIT_ID,
    publicFields,
    result.params,
    fieldLabels,
  );
  if (nativeContext.activeStateLeafPathElements) {
    processOneWitness.active_state_leaf_path_0 = splitVector4(
      nativeContext.activeStateLeafPathElements[0],
      'nativeActiveStateLeafPathElements[0]',
    );
    processOneWitness.active_state_leaf_path_1 = splitVector4(
      nativeContext.activeStateLeafPathElements[1],
      'nativeActiveStateLeafPathElements[1]',
    );
  }
  const nativeWitness = {
    is_quadratic_cost: splitObject(result.derived.isQuadraticCost, 'isQuadraticCost'),
    num_signups: splitObject(result.derived.numSignUps, 'numSignUps'),
    max_vote_options: splitObject(result.derived.maxVoteOptions, 'maxVoteOptions'),
    enc_pub_key: splitVector2(rawInput.encPubKeys[messageIndex], 'encPubKey'),
    msg: splitVector10(rawInput.msgs[messageIndex], 'msg'),
    coord_priv_key: splitObject(rawInput.coordPrivKey, 'coordPrivKey'),
    current_state_salt: splitObject(rawInput.currentStateSalt, 'currentStateSalt'),
    new_state_salt: splitObject(rawInput.newStateSalt, 'newStateSalt'),
    process_one: processOneWitness,
  };

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: nativeWitness,
    },
    full_witness: {
      processMessages: rawInput,
      messageIndex,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

function buildNativeProcessMessageStepCoreWitness(witness) {
  return {
    is_quadratic_cost: witness.is_quadratic_cost,
    num_signups: witness.num_signups,
    max_vote_options: witness.max_vote_options,
    enc_pub_key: witness.enc_pub_key,
    msg: witness.msg,
    coord_priv_key: witness.coord_priv_key,
    current_state_salt: witness.current_state_salt,
    new_state_salt: witness.new_state_salt,
    process_one: witness.process_one,
  };
}

function pushU256(args, value) {
  args.push(value.low, value.high);
}

function pushFelt(args, value) {
  args.push(BigInt(value));
}

function pushVector2(args, value) {
  pushU256(args, value.v0);
  pushU256(args, value.v1);
}

function pushVector3(args, value) {
  pushU256(args, value.v0);
  pushU256(args, value.v1);
  pushU256(args, value.v2);
}

function pushVector4(args, value) {
  pushU256(args, value.v0);
  pushU256(args, value.v1);
  pushU256(args, value.v2);
  pushU256(args, value.v3);
}

function pushVector7(args, value) {
  pushU256(args, value.v0);
  pushU256(args, value.v1);
  pushU256(args, value.v2);
  pushU256(args, value.v3);
  pushU256(args, value.v4);
  pushU256(args, value.v5);
  pushU256(args, value.v6);
}

function pushVector10(args, value) {
  pushU256(args, value.v0);
  pushU256(args, value.v1);
  pushU256(args, value.v2);
  pushU256(args, value.v3);
  pushU256(args, value.v4);
  pushU256(args, value.v5);
  pushU256(args, value.v6);
  pushU256(args, value.v7);
  pushU256(args, value.v8);
  pushU256(args, value.v9);
}

function pushProcessOneStateTransitionWitness(args, witness) {
  pushU256(args, witness.is_quadratic_cost);
  pushU256(args, witness.num_signups);
  pushU256(args, witness.max_vote_options);
  pushU256(args, witness.expected_poll_id);
  pushU256(args, witness.is_signature_valid);
  pushU256(args, witness.is_decryption_active);
  pushVector10(args, witness.msg);
  pushVector2(args, witness.shared_key);
  pushVector7(args, witness.decrypted_command);
  pushVector3(args, witness.packed_command);
  pushU256(args, witness.cmd_salt);
  pushVector2(args, witness.cmd_sig_r8);
  pushU256(args, witness.cmd_sig_s);
  pushU256(args, witness.current_state_root);
  pushU256(args, witness.active_state_root);
  pushVector10(args, witness.state_leaf);
  pushVector2(args, witness.state_decrypted_point);
  pushVector4(args, witness.state_leaf_path_0);
  pushVector4(args, witness.state_leaf_path_1);
  pushU256(args, witness.active_state_leaf);
  pushVector4(args, witness.active_state_leaf_path_0);
  pushVector4(args, witness.active_state_leaf_path_1);
  pushU256(args, witness.current_vote_weight);
  pushVector4(args, witness.current_vote_weight_path);
  pushU256(args, witness.is_valid);
  pushU256(args, witness.cmd_state_index);
  pushU256(args, witness.cmd_vote_option_index);
  pushU256(args, witness.cmd_new_vote_weight);
  pushU256(args, witness.cmd_nonce);
  pushU256(args, witness.cmd_poll_id);
  pushVector2(args, witness.cmd_new_pub_key);
  pushU256(args, witness.new_balance);
  pushU256(args, witness.new_sl_nonce);
}

function pushNativeProcessMessageCoordKeyFields(args, fields) {
  pushFelt(args, fields.coord_pub_key_hash);
  pushFelt(args, fields.coord_priv_key_hash);
  pushFelt(args, fields.coord_key_binding_hash);
}

function pushNativeProcessMessageEcdhFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.coord_priv_key_hash);
  pushFelt(args, fields.enc_pub_key_hash);
  pushFelt(args, fields.shared_key_hash);
  pushFelt(args, fields.shared_key_binding_hash);
}

function pushNativeProcessMessageEcdhWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.enc_pub_key);
  pushVector2(args, witness.shared_key);
}

function pushNativeProcessMessageDecryptFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.coord_priv_key_hash);
  pushFelt(args, fields.c1_hash);
  pushFelt(args, fields.c2_hash);
  pushFelt(args, fields.decrypt_is_odd);
  pushFelt(args, fields.decrypt_binding_hash);
}

function pushNativeProcessMessageDecryptWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.c1);
  pushVector2(args, witness.c2);
  pushVector2(args, witness.decrypted_point);
}

function pushNativeProcessMessageSignatureFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.pub_key_hash);
  pushFelt(args, fields.r8_hash);
  pushFelt(args, fields.packed_command_hash);
  pushFelt(args, fields.cmd_sig_s_hash);
  pushFelt(args, fields.command_auth_hash);
  pushFelt(args, fields.is_signature_valid);
}

function pushNativeProcessMessageSignatureWitness(args, witness) {
  pushVector2(args, witness.pub_key);
  pushVector2(args, witness.r8);
  pushU256(args, witness.s);
  pushVector3(args, witness.packed_command);
  pushU256(args, witness.cmd_salt);
}

function pushNativeProcessMessageStepCoreFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.packed_vals_hash);
  pushFelt(args, fields.coord_priv_key_hash);
  pushFelt(args, fields.previous_message_hash);
  pushFelt(args, fields.next_message_hash);
  pushFelt(args, fields.current_state_root_hash);
  pushFelt(args, fields.new_state_root_hash);
  pushFelt(args, fields.current_state_commitment_hash);
  pushFelt(args, fields.new_state_commitment_hash);
  pushFelt(args, fields.active_state_root_hash);
  pushFelt(args, fields.expected_poll_id);
  pushFelt(args, fields.enc_pub_key_hash);
  pushFelt(args, fields.shared_key_hash);
  pushFelt(args, fields.shared_key_binding_hash);
  pushFelt(args, fields.state_ciphertext_c1_hash);
  pushFelt(args, fields.state_ciphertext_c2_hash);
  pushFelt(args, fields.state_decrypt_is_odd);
  pushFelt(args, fields.state_decrypt_binding_hash);
  pushFelt(args, fields.signature_pub_key_hash);
  pushFelt(args, fields.signature_r8_hash);
  pushFelt(args, fields.packed_command_hash);
  pushFelt(args, fields.cmd_sig_s_hash);
  pushFelt(args, fields.command_auth_hash);
  pushFelt(args, fields.command_plaintext_binding_hash);
  pushFelt(args, fields.is_signature_valid);
}

function pushNativeProcessMessageCoordKeyWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.coord_pub_key);
}

function pushNativeProcessMessageStepCoreWitness(args, witness) {
  pushU256(args, witness.is_quadratic_cost);
  pushU256(args, witness.num_signups);
  pushU256(args, witness.max_vote_options);
  pushVector2(args, witness.enc_pub_key);
  pushVector10(args, witness.msg);
  pushU256(args, witness.coord_priv_key);
  pushU256(args, witness.current_state_salt);
  pushU256(args, witness.new_state_salt);
  pushProcessOneStateTransitionWitness(args, witness.process_one);
}

export function serializeNativeCairoProcessMessageCoordKeyExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessMessageCoordKeyFields(args, cairoInput.program_input.fields);
  pushNativeProcessMessageCoordKeyWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessMessageEcdhExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessMessageEcdhFields(args, cairoInput.program_input.fields);
  pushNativeProcessMessageEcdhWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessMessageDecryptExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessMessageDecryptFields(args, cairoInput.program_input.fields);
  pushNativeProcessMessageDecryptWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessMessageSignatureExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessMessageSignatureFields(args, cairoInput.program_input.fields);
  pushNativeProcessMessageSignatureWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessMessageStepCoreExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessMessageStepCoreFields(args, cairoInput.program_input.fields);
  pushNativeProcessMessageStepCoreWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}
