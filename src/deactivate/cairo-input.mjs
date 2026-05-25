import { bigintToHex, decimalize, splitU256ToU128 } from '../encoding.mjs';
import {
  NATIVE_PUBLIC_OUTPUT_VERSION,
  PROCESS_DEACTIVATE_COORD_KEY_NATIVE_CIRCUIT_ID,
  PROCESS_DEACTIVATE_DECRYPT_NATIVE_CIRCUIT_ID,
  PROCESS_DEACTIVATE_ECDH_NATIVE_CIRCUIT_ID,
  PROCESS_DEACTIVATE_NATIVE_COMMAND_AUTH_DOMAIN,
  PROCESS_DEACTIVATE_NATIVE_COMMAND_PLAINTEXT_DOMAIN,
  PROCESS_DEACTIVATE_NATIVE_COORD_KEY_BINDING_DOMAIN,
  PROCESS_DEACTIVATE_NATIVE_DECRYPT_BINDING_DOMAIN,
  PROCESS_DEACTIVATE_NATIVE_SHARED_KEY_DOMAIN,
  PROCESS_DEACTIVATE_SIGNATURE_NATIVE_CIRCUIT_ID,
  PROCESS_DEACTIVATE_STEP_CORE_NATIVE_CIRCUIT_ID,
  PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
  PUBLIC_OUTPUT_MAGIC,
  SMALL_PROCESS_DEACTIVATE_PARAMS,
  STARKNET_POSEIDON_HASH_SCHEME,
} from '../constants.mjs';
import { poseidonManyFelts } from '../integrity/hashes.mjs';
import { toStarkFelt } from '../tally/native-tally-votes.mjs';
import { evaluateProcessDeactivateMessagesStateful } from './process-deactivate-messages.mjs';
import { nativeProcessDeactivateTransitionContexts } from './native-process-roots.mjs';
import { evaluateNativeProcessDeactivateMessagesBoundary } from './native-process-deactivate-messages.mjs';
import {
  buildNativeCairoProcessDeactivateBoundaryInput,
  serializeNativeCairoProcessDeactivateBoundaryExecutableArgs,
} from './native-cairo-input.mjs';

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

function nativeDeactivateCoordKeyBindingHash(coordPubKeyHash, coordPrivKeyHash) {
  return nativeHashFelts(
    [PROCESS_DEACTIVATE_NATIVE_COORD_KEY_BINDING_DOMAIN, coordPubKeyHash, coordPrivKeyHash],
    'deactivateCoordKeyBinding',
  );
}

function nativePackedCmdHash(packedCmd) {
  if (!Array.isArray(packedCmd) || packedCmd.length !== 3) {
    throw new Error('packedCmd must contain three values');
  }
  return nativeHashFelts(packedCmd, 'packedCmd');
}

function nativeDeactivateCommandAuthHash(pubKeyHash, r8Hash, packedCmdHash, cmdSigSHash, cmdSalt, signatureValid) {
  return nativeHashFelts(
    [
      PROCESS_DEACTIVATE_NATIVE_COMMAND_AUTH_DOMAIN,
      pubKeyHash,
      r8Hash,
      packedCmdHash,
      cmdSigSHash,
      cmdSalt,
      signatureValid,
    ],
    'deactivateCommandAuth',
  );
}

function nativeDeactivateCommandPlaintextBindingHash(
  nextMessageHash,
  sharedKeyHash,
  packedCmdHash,
  signaturePubKeyHash,
  signatureR8Hash,
  cmdSigSHash,
  commandAuthHash,
) {
  return nativeHashFelts(
    [
      PROCESS_DEACTIVATE_NATIVE_COMMAND_PLAINTEXT_DOMAIN,
      nextMessageHash,
      sharedKeyHash,
      packedCmdHash,
      signaturePubKeyHash,
      signatureR8Hash,
      cmdSigSHash,
      commandAuthHash,
    ],
    'deactivateCommandPlaintextBinding',
  );
}

function nativeDeactivateSharedKeyBindingHash(ecdhKind, coordPrivKeyHash, baseHash, sharedKeyHash) {
  return nativeHashFelts(
    [
      PROCESS_DEACTIVATE_NATIVE_SHARED_KEY_DOMAIN,
      ecdhKind,
      coordPrivKeyHash,
      baseHash,
      sharedKeyHash,
    ],
    'deactivateSharedKeyBinding',
  );
}

function nativeDeactivateDecryptBindingHash(decryptKind, coordPrivKeyHash, c1Hash, c2Hash, decryptIsOdd) {
  return nativeHashFelts(
    [
      PROCESS_DEACTIVATE_NATIVE_DECRYPT_BINDING_DOMAIN,
      decryptKind,
      coordPrivKeyHash,
      c1Hash,
      c2Hash,
      decryptIsOdd,
    ],
    'deactivateDecryptBinding',
  );
}

function nativeDeactivateMessageHash(message, encPubKey, previousHash) {
  return nativeHashFelts([...message, encPubKey[0], encPubKey[1], previousHash], 'messageHash');
}

function nativeDeactivateMessageHashOrEmpty(message, encPubKey, previousHash) {
  return nativeFelt(message[0], 'message[0]') === 0n
    ? nativeFelt(previousHash, 'previousHash')
    : nativeDeactivateMessageHash(message, encPubKey, previousHash);
}

function nativeDeactivateMessageHashChain(messages, encPubKeys, batchStartHash) {
  const chain = [nativeFelt(batchStartHash, 'batchStartHash')];
  for (let index = 0; index < messages.length; index += 1) {
    chain.push(nativeDeactivateMessageHashOrEmpty(messages[index], encPubKeys[index], chain[index]));
  }
  return chain;
}

function nativeCommitment(left, right, label) {
  return nativeHashFelts([left, right], label);
}

function nativeProcessDeactivatePublicOutput(circuitId, fields, params, fieldLabels) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'hash_scheme',
    'state_tree_depth',
    'deactivate_tree_depth',
    'message_batch_size',
    ...fieldLabels,
  ];
  const felts = [
    PUBLIC_OUTPUT_MAGIC,
    NATIVE_PUBLIC_OUTPUT_VERSION,
    circuitId,
    STARKNET_POSEIDON_HASH_SCHEME,
    BigInt(params.stateTreeDepth),
    BigInt(params.deactivateTreeDepth),
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

function assertMessageIndex(messageIndex) {
  const maxMessageIndex = SMALL_PROCESS_DEACTIVATE_PARAMS.messageBatchSize - 1;
  if (!Number.isInteger(messageIndex) || messageIndex < 0 || messageIndex > maxMessageIndex) {
    throw new Error(`messageIndex must be an integer in [0, ${maxMessageIndex}]`);
  }
}

function isEmptyDeactivateMessage(rawInput, messageIndex) {
  return BigInt(rawInput.msgs[messageIndex][0]) === 0n;
}

export function buildNativeCairoProcessDeactivateCoordKeyInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const coordPubKeyHash = nativeHashPoint(rawInput.coordPubKey, 'coordPubKey');
  const coordPrivKeyHash = nativeCoordPrivKeyHash(result.state.input.coordPrivKey);
  const publicFields = {
    coord_pub_key_hash: coordPubKeyHash,
    coord_priv_key_hash: coordPrivKeyHash,
    coord_key_binding_hash: nativeDeactivateCoordKeyBindingHash(coordPubKeyHash, coordPrivKeyHash),
  };
  const fields = {
    coord_pub_key_hash: feltObject(publicFields.coord_pub_key_hash),
    coord_priv_key_hash: feltObject(publicFields.coord_priv_key_hash),
    coord_key_binding_hash: feltObject(publicFields.coord_key_binding_hash),
  };
  const publicOutput = nativeProcessDeactivatePublicOutput(
    PROCESS_DEACTIVATE_COORD_KEY_NATIVE_CIRCUIT_ID,
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
        coord_priv_key: splitObject(result.state.input.coordPrivKey, 'coordPrivKey'),
        coord_pub_key: splitVector2(rawInput.coordPubKey, 'coordPubKey'),
      },
    },
    full_witness: {
      processDeactivate: rawInput,
      nativeCoordKeyBinding: true,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessDeactivateEcdhInput(
  rawInput,
  messageIndex,
  ecdhKind = 'command',
  evaluated,
) {
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const command = result.derived.messageCommands[messageIndex];
  const ecdhKindFelt = ecdhKind === 'leaf' ? 1n : 0n;
  const base = ecdhKind === 'leaf'
    ? transition.input.stateLeaf.slice(0, 2)
    : rawInput.encPubKeys[messageIndex].map(BigInt);
  const expectedSharedKey = ecdhKind === 'leaf' ? transition.derived.sharedKey : command.sharedKey;
  const coordPrivKeyHash = nativeCoordPrivKeyHash(result.state.input.coordPrivKey);
  const baseHash = nativeHashPoint(base, 'base');
  const sharedKeyHash = nativeHashPoint(expectedSharedKey, 'sharedKey');
  const publicFields = {
    message_index: BigInt(messageIndex),
    ecdh_kind: ecdhKindFelt,
    coord_priv_key_hash: coordPrivKeyHash,
    base_hash: baseHash,
    shared_key_hash: sharedKeyHash,
    shared_key_binding_hash: nativeDeactivateSharedKeyBindingHash(
      ecdhKindFelt,
      coordPrivKeyHash,
      baseHash,
      sharedKeyHash,
    ),
  };
  const fields = {
    message_index: feltObject(publicFields.message_index),
    ecdh_kind: feltObject(publicFields.ecdh_kind),
    coord_priv_key_hash: feltObject(publicFields.coord_priv_key_hash),
    base_hash: feltObject(publicFields.base_hash),
    shared_key_hash: feltObject(publicFields.shared_key_hash),
    shared_key_binding_hash: feltObject(publicFields.shared_key_binding_hash),
  };
  const publicOutput = nativeProcessDeactivatePublicOutput(
    PROCESS_DEACTIVATE_ECDH_NATIVE_CIRCUIT_ID,
    publicFields,
    result.params,
    [
      'message_index',
      'ecdh_kind',
      'coord_priv_key_hash',
      'base_hash',
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
        coord_priv_key: splitObject(result.state.input.coordPrivKey, 'coordPrivKey'),
        base: splitVector2(base, 'base'),
        shared_key: splitVector2(expectedSharedKey, 'sharedKey'),
      },
    },
    full_witness: {
      processDeactivate: rawInput,
      messageIndex,
      ecdhKind,
      nativeSharedKey: true,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessDeactivateSignatureInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  if (isEmptyDeactivateMessage(rawInput, messageIndex)) {
    throw new Error('cannot build native deactivate signature proof for an empty message slot');
  }
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const input = transition.input;
  const command = result.derived.messageCommands[messageIndex];
  const cmdSalt = command.decryptedCommand[3];
  const pubKeyHash = nativeHashPoint(input.stateLeaf.slice(0, 2), 'pubKey');
  const r8Hash = nativeHashPoint(input.cmdSigR8, 'r8');
  const packedCmdHash = nativePackedCmdHash(input.packedCmd);
  const cmdSigSHash = nativeHashU256(input.cmdSigS, 'cmdSigS');
  const publicFields = {
    message_index: BigInt(messageIndex),
    pub_key_hash: pubKeyHash,
    r8_hash: r8Hash,
    packed_cmd_hash: packedCmdHash,
    cmd_sig_s_hash: cmdSigSHash,
    command_auth_hash: nativeDeactivateCommandAuthHash(
      pubKeyHash,
      r8Hash,
      packedCmdHash,
      cmdSigSHash,
      cmdSalt,
      transition.derived.signatureValid,
    ),
    signature_valid: transition.derived.signatureValid,
  };
  const fields = {
    message_index: feltObject(publicFields.message_index),
    pub_key_hash: feltObject(publicFields.pub_key_hash),
    r8_hash: feltObject(publicFields.r8_hash),
    packed_cmd_hash: feltObject(publicFields.packed_cmd_hash),
    cmd_sig_s_hash: feltObject(publicFields.cmd_sig_s_hash),
    command_auth_hash: feltObject(publicFields.command_auth_hash),
    signature_valid: feltObject(publicFields.signature_valid),
  };
  const publicOutput = nativeProcessDeactivatePublicOutput(
    PROCESS_DEACTIVATE_SIGNATURE_NATIVE_CIRCUIT_ID,
    publicFields,
    result.params,
    [
      'message_index',
      'pub_key_hash',
      'r8_hash',
      'packed_cmd_hash',
      'cmd_sig_s_hash',
      'command_auth_hash',
      'signature_valid',
    ],
  );

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        pub_key: splitVector2(input.stateLeaf.slice(0, 2), 'pubKey'),
        r8: splitVector2(input.cmdSigR8, 'r8'),
        s: splitObject(input.cmdSigS, 's'),
        packed_cmd: splitVector3(input.packedCmd, 'packedCmd'),
        cmd_salt: splitObject(cmdSalt, 'cmdSalt'),
      },
    },
    full_witness: {
      processDeactivate: rawInput,
      messageIndex,
      nativeAuth: true,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessDeactivateDecryptInput(
  rawInput,
  messageIndex,
  decryptKind = 'current',
  evaluated,
) {
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const current = decryptKind === 'current';
  const c1 = current ? transition.input.stateLeaf.slice(5, 7) : transition.input.c1;
  const c2 = current ? transition.input.stateLeaf.slice(7, 9) : transition.input.c2;
  const decrypt = current ? transition.derived.currentStateDecrypt : transition.derived.newStateDecrypt;
  const decryptKindFelt = current ? 0n : 1n;
  const coordPrivKeyHash = nativeCoordPrivKeyHash(result.state.input.coordPrivKey);
  const c1Hash = nativeHashPoint(c1, 'c1');
  const c2Hash = nativeHashPoint(c2, 'c2');
  const publicFields = {
    message_index: BigInt(messageIndex),
    decrypt_kind: decryptKindFelt,
    coord_priv_key_hash: coordPrivKeyHash,
    c1_hash: c1Hash,
    c2_hash: c2Hash,
    decrypt_is_odd: decrypt.isOdd,
    decrypt_binding_hash: nativeDeactivateDecryptBindingHash(
      decryptKindFelt,
      coordPrivKeyHash,
      c1Hash,
      c2Hash,
      decrypt.isOdd,
    ),
  };
  const fields = {
    message_index: feltObject(publicFields.message_index),
    decrypt_kind: feltObject(publicFields.decrypt_kind),
    coord_priv_key_hash: feltObject(publicFields.coord_priv_key_hash),
    c1_hash: feltObject(publicFields.c1_hash),
    c2_hash: feltObject(publicFields.c2_hash),
    decrypt_is_odd: feltObject(publicFields.decrypt_is_odd),
    decrypt_binding_hash: feltObject(publicFields.decrypt_binding_hash),
  };
  const publicOutput = nativeProcessDeactivatePublicOutput(
    PROCESS_DEACTIVATE_DECRYPT_NATIVE_CIRCUIT_ID,
    publicFields,
    result.params,
    [
      'message_index',
      'decrypt_kind',
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
        coord_priv_key: splitObject(result.state.input.coordPrivKey, 'coordPrivKey'),
        c1: splitVector2(c1, 'c1'),
        c2: splitVector2(c2, 'c2'),
        decrypted_point: splitVector2(decrypt.decryptedPoint, 'decryptedPoint'),
      },
    },
    full_witness: {
      processDeactivate: rawInput,
      messageIndex,
      decryptKind,
      nativeDecryptBinding: true,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessDeactivateStepCoreInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  if (isEmptyDeactivateMessage(rawInput, messageIndex)) {
    throw new Error('cannot build native deactivate core proof for an empty message slot');
  }
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const input = transition.input;
  const command = result.derived.messageCommands[messageIndex];
  const nativeContext = nativeProcessDeactivateTransitionContexts(result.state, rawInput)[messageIndex];
  const nativeMsgChain = nativeDeactivateMessageHashChain(
    rawInput.msgs,
    rawInput.encPubKeys,
    rawInput.batchStartHash,
  );
  const signaturePubKeyHash = nativeHashPoint(input.stateLeaf.slice(0, 2), 'signaturePubKey');
  const signatureR8Hash = nativeHashPoint(input.cmdSigR8, 'signatureR8');
  const packedCmdHash = nativePackedCmdHash(input.packedCmd);
  const cmdSigSHash = nativeHashU256(input.cmdSigS, 'cmdSigS');
  const coordPrivKeyHash = nativeCoordPrivKeyHash(result.state.input.coordPrivKey);
  const encPubKeyHash = nativeHashPoint(rawInput.encPubKeys[messageIndex], 'encPubKey');
  const commandSharedKeyHash = nativeHashPoint(command.sharedKey, 'commandSharedKey');
  const deactivatePubKeyHash = nativeHashPoint(input.stateLeaf.slice(0, 2), 'deactivatePubKey');
  const deactivateSharedKeyHash = nativeHashPoint(transition.derived.sharedKey, 'deactivateSharedKey');
  const currentStateCiphertextC1Hash = nativeHashPoint(
    input.stateLeaf.slice(5, 7),
    'currentStateCiphertextC1',
  );
  const currentStateCiphertextC2Hash = nativeHashPoint(
    input.stateLeaf.slice(7, 9),
    'currentStateCiphertextC2',
  );
  const newStateCiphertextC1Hash = nativeHashPoint(input.c1, 'newStateCiphertextC1');
  const newStateCiphertextC2Hash = nativeHashPoint(input.c2, 'newStateCiphertextC2');
  const nextMessageHash = nativeMsgChain[messageIndex + 1];
  const commandAuthHash = nativeDeactivateCommandAuthHash(
    signaturePubKeyHash,
    signatureR8Hash,
    packedCmdHash,
    cmdSigSHash,
    command.decryptedCommand[3],
    transition.derived.signatureValid,
  );
  const publicFields = {
    message_index: BigInt(messageIndex),
    deactivate_index: BigInt(input.deactivateIndex),
    coord_priv_key_hash: coordPrivKeyHash,
    previous_message_hash: nativeMsgChain[messageIndex],
    next_message_hash: nextMessageHash,
    current_active_state_root_hash: nativeContext.currentActiveStateRoot,
    current_deactivate_root_hash: nativeContext.currentDeactivateRoot,
    new_active_state_root_hash: nativeContext.newActiveStateRoot,
    new_deactivate_root_hash: nativeContext.newDeactivateRoot,
    current_deactivate_commitment_hash: nativeCommitment(
      nativeContext.currentActiveStateRoot,
      nativeContext.currentDeactivateRoot,
      'currentDeactivateCommitment',
    ),
    new_deactivate_commitment_hash: nativeCommitment(
      nativeContext.newActiveStateRoot,
      nativeContext.newDeactivateRoot,
      'newDeactivateCommitment',
    ),
    current_state_root_hash: nativeContext.currentStateRoot,
    expected_poll_id: result.publicFields.expectedPollId,
    enc_pub_key_hash: encPubKeyHash,
    command_shared_key_hash: commandSharedKeyHash,
    command_shared_key_binding_hash: nativeDeactivateSharedKeyBindingHash(
      0n,
      coordPrivKeyHash,
      encPubKeyHash,
      commandSharedKeyHash,
    ),
    signature_pub_key_hash: signaturePubKeyHash,
    signature_r8_hash: signatureR8Hash,
    packed_cmd_hash: packedCmdHash,
    cmd_sig_s_hash: cmdSigSHash,
    command_auth_hash: commandAuthHash,
    command_plaintext_binding_hash: nativeDeactivateCommandPlaintextBindingHash(
      nextMessageHash,
      commandSharedKeyHash,
      packedCmdHash,
      signaturePubKeyHash,
      signatureR8Hash,
      cmdSigSHash,
      commandAuthHash,
    ),
    signature_valid: transition.derived.signatureValid,
    current_state_ciphertext_c1_hash: currentStateCiphertextC1Hash,
    current_state_ciphertext_c2_hash: currentStateCiphertextC2Hash,
    current_decrypt_is_odd: transition.derived.currentStateDecrypt.isOdd,
    current_decrypt_binding_hash: nativeDeactivateDecryptBindingHash(
      0n,
      coordPrivKeyHash,
      currentStateCiphertextC1Hash,
      currentStateCiphertextC2Hash,
      transition.derived.currentStateDecrypt.isOdd,
    ),
    new_state_ciphertext_c1_hash: newStateCiphertextC1Hash,
    new_state_ciphertext_c2_hash: newStateCiphertextC2Hash,
    new_decrypt_is_odd: transition.derived.newStateDecrypt.isOdd,
    new_decrypt_binding_hash: nativeDeactivateDecryptBindingHash(
      1n,
      coordPrivKeyHash,
      newStateCiphertextC1Hash,
      newStateCiphertextC2Hash,
      transition.derived.newStateDecrypt.isOdd,
    ),
    deactivate_pub_key_hash: deactivatePubKeyHash,
    deactivate_shared_key_hash: deactivateSharedKeyHash,
    deactivate_shared_key_binding_hash: nativeDeactivateSharedKeyBindingHash(
      1n,
      coordPrivKeyHash,
      deactivatePubKeyHash,
      deactivateSharedKeyHash,
    ),
  };
  const fields = Object.fromEntries(
    Object.entries(publicFields).map(([key, value]) => [key, feltObject(value)]),
  );
  const fieldLabels = [
    'message_index',
    'deactivate_index',
    'coord_priv_key_hash',
    'previous_message_hash',
    'next_message_hash',
    'current_active_state_root_hash',
    'current_deactivate_root_hash',
    'new_active_state_root_hash',
    'new_deactivate_root_hash',
    'current_deactivate_commitment_hash',
    'new_deactivate_commitment_hash',
    'current_state_root_hash',
    'expected_poll_id',
    'enc_pub_key_hash',
    'command_shared_key_hash',
    'command_shared_key_binding_hash',
    'signature_pub_key_hash',
    'signature_r8_hash',
    'packed_cmd_hash',
    'cmd_sig_s_hash',
    'command_auth_hash',
    'command_plaintext_binding_hash',
    'signature_valid',
    'current_state_ciphertext_c1_hash',
    'current_state_ciphertext_c2_hash',
    'current_decrypt_is_odd',
    'current_decrypt_binding_hash',
    'new_state_ciphertext_c1_hash',
    'new_state_ciphertext_c2_hash',
    'new_decrypt_is_odd',
    'new_decrypt_binding_hash',
    'deactivate_pub_key_hash',
    'deactivate_shared_key_hash',
    'deactivate_shared_key_binding_hash',
  ];
  const publicOutput = nativeProcessDeactivatePublicOutput(
    PROCESS_DEACTIVATE_STEP_CORE_NATIVE_CIRCUIT_ID,
    publicFields,
    result.params,
    fieldLabels,
  );
  const nativeWitness = {
    is_empty_msg: splitObject(input.isEmptyMsg, 'isEmptyMsg'),
    coord_priv_key: splitObject(result.state.input.coordPrivKey, 'coordPrivKey'),
    msg: splitVector10(rawInput.msgs[messageIndex], 'msg'),
    enc_pub_key: splitVector2(rawInput.encPubKeys[messageIndex], 'encPubKey'),
    command_shared_key: splitVector2(command.sharedKey, 'commandSharedKey'),
    decrypted_command: splitVector7(command.decryptedCommand, 'decryptedCommand'),
    c1: splitVector2(input.c1, 'c1'),
    c2: splitVector2(input.c2, 'c2'),
    state_leaf: splitVector10(input.stateLeaf, 'stateLeaf'),
    current_decrypted_point: splitVector2(
      transition.derived.currentStateDecrypt.decryptedPoint,
      'currentDecryptedPoint',
    ),
    new_decrypted_point: splitVector2(
      transition.derived.newStateDecrypt.decryptedPoint,
      'newDecryptedPoint',
    ),
    state_leaf_path_0: splitVector4(
      nativeContext.stateLeafPathElements[0],
      'nativeStateLeafPathElements[0]',
    ),
    state_leaf_path_1: splitVector4(
      nativeContext.stateLeafPathElements[1],
      'nativeStateLeafPathElements[1]',
    ),
    active_state_leaf_path_0: splitVector4(
      nativeContext.activeStateLeafPathElements[0],
      'nativeActiveStateLeafPathElements[0]',
    ),
    active_state_leaf_path_1: splitVector4(
      nativeContext.activeStateLeafPathElements[1],
      'nativeActiveStateLeafPathElements[1]',
    ),
    current_active_state: splitObject(input.currentActiveState, 'currentActiveState'),
    new_active_state: splitObject(input.newActiveState, 'newActiveState'),
    cmd_state_index: splitObject(input.cmdStateIndex, 'cmdStateIndex'),
    cmd_poll_id: splitObject(input.cmdPollId, 'cmdPollId'),
    cmd_sig_r8: splitVector2(input.cmdSigR8, 'cmdSigR8'),
    cmd_sig_s: splitObject(input.cmdSigS, 'cmdSigS'),
    packed_cmd: splitVector3(input.packedCmd, 'packedCmd'),
    deactivate_leaf_path_0: splitVector4(
      nativeContext.deactivateLeafPathElements[0],
      'nativeDeactivateLeafPathElements[0]',
    ),
    deactivate_leaf_path_1: splitVector4(
      nativeContext.deactivateLeafPathElements[1],
      'nativeDeactivateLeafPathElements[1]',
    ),
    deactivate_leaf_path_2: splitVector4(
      nativeContext.deactivateLeafPathElements[2],
      'nativeDeactivateLeafPathElements[2]',
    ),
    deactivate_leaf_path_3: splitVector4(
      nativeContext.deactivateLeafPathElements[3],
      'nativeDeactivateLeafPathElements[3]',
    ),
    current_decrypt_is_odd: splitObject(transition.derived.currentStateDecrypt.isOdd, 'currentDecryptIsOdd'),
    new_decrypt_is_odd: splitObject(transition.derived.newStateDecrypt.isOdd, 'newDecryptIsOdd'),
    signature_valid: splitObject(transition.derived.signatureValid, 'signatureValid'),
    deactivate_shared_key: splitVector2(transition.derived.sharedKey, 'deactivateSharedKey'),
  };

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: nativeWitness,
    },
    full_witness: {
      processDeactivate: rawInput,
      messageIndex,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessDeactivateStageInput(rawInput, evaluatedBoundary) {
  const boundaryEvaluation = evaluatedBoundary ?? evaluateNativeProcessDeactivateMessagesBoundary(rawInput);
  const boundary = buildNativeCairoProcessDeactivateBoundaryInput(rawInput, boundaryEvaluation);
  const stateful = evaluateProcessDeactivateMessagesStateful(rawInput);
  const coordKey = buildNativeCairoProcessDeactivateCoordKeyInput(rawInput, stateful);
  const messages = [];

  for (let messageIndex = 0; messageIndex < boundaryEvaluation.params.messageBatchSize; messageIndex += 1) {
    messages.push({
      commandEcdh: buildNativeCairoProcessDeactivateEcdhInput(
        rawInput,
        messageIndex,
        'command',
        stateful,
      ),
      leafEcdh: buildNativeCairoProcessDeactivateEcdhInput(
        rawInput,
        messageIndex,
        'leaf',
        stateful,
      ),
      signature: buildNativeCairoProcessDeactivateSignatureInput(rawInput, messageIndex, stateful),
      currentDecrypt: buildNativeCairoProcessDeactivateDecryptInput(
        rawInput,
        messageIndex,
        'current',
        stateful,
      ),
      newDecrypt: buildNativeCairoProcessDeactivateDecryptInput(
        rawInput,
        messageIndex,
        'new',
        stateful,
      ),
      core: buildNativeCairoProcessDeactivateStepCoreInput(rawInput, messageIndex, stateful),
    });
  }

  return {
    fields: boundary.fields,
    witness_summary: boundary.witness_summary,
    program_input: {
      boundary: boundary.program_input,
      coord_key: coordKey.program_input,
      messages: messages.map((message) => ({
        command_ecdh: message.commandEcdh.program_input,
        leaf_ecdh: message.leafEcdh.program_input,
        signature: message.signature.program_input,
        current_decrypt: message.currentDecrypt.program_input,
        new_decrypt: message.newDecrypt.program_input,
        core: message.core.program_input,
      })),
    },
    components: {
      boundary,
      coordKey,
      messages,
    },
    public_output_labels: boundary.public_output_labels,
    public_output: boundary.public_output,
  };
}

function buildNativeProcessDeactivateStepCoreWitness(witness) {
  return {
    is_empty_msg: witness.is_empty_msg,
    coord_priv_key: witness.coord_priv_key,
    msg: witness.msg,
    enc_pub_key: witness.enc_pub_key,
    command_shared_key: witness.command_shared_key,
    decrypted_command: witness.decrypted_command,
    c1: witness.c1,
    c2: witness.c2,
    state_leaf: witness.state_leaf,
    state_leaf_path_0: witness.state_leaf_path_0,
    state_leaf_path_1: witness.state_leaf_path_1,
    active_state_leaf_path_0: witness.active_state_leaf_path_0,
    active_state_leaf_path_1: witness.active_state_leaf_path_1,
    current_active_state: witness.current_active_state,
    new_active_state: witness.new_active_state,
    cmd_state_index: witness.cmd_state_index,
    cmd_poll_id: witness.cmd_poll_id,
    cmd_sig_r8: witness.cmd_sig_r8,
    cmd_sig_s: witness.cmd_sig_s,
    packed_cmd: witness.packed_cmd,
    deactivate_leaf_path_0: witness.deactivate_leaf_path_0,
    deactivate_leaf_path_1: witness.deactivate_leaf_path_1,
    deactivate_leaf_path_2: witness.deactivate_leaf_path_2,
    deactivate_leaf_path_3: witness.deactivate_leaf_path_3,
    current_decrypt_is_odd: witness.current_decrypt_is_odd,
    new_decrypt_is_odd: witness.new_decrypt_is_odd,
    signature_valid: witness.signature_valid,
    deactivate_shared_key: witness.deactivate_shared_key,
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

function pushNativeProcessDeactivateCoordKeyFields(args, fields) {
  pushFelt(args, fields.coord_pub_key_hash);
  pushFelt(args, fields.coord_priv_key_hash);
  pushFelt(args, fields.coord_key_binding_hash);
}

function pushNativeProcessDeactivateCoordKeyWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.coord_pub_key);
}

function pushNativeProcessDeactivateEcdhFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.ecdh_kind);
  pushFelt(args, fields.coord_priv_key_hash);
  pushFelt(args, fields.base_hash);
  pushFelt(args, fields.shared_key_hash);
  pushFelt(args, fields.shared_key_binding_hash);
}

function pushNativeProcessDeactivateEcdhWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.base);
  pushVector2(args, witness.shared_key);
}

function pushNativeProcessDeactivateSignatureFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.pub_key_hash);
  pushFelt(args, fields.r8_hash);
  pushFelt(args, fields.packed_cmd_hash);
  pushFelt(args, fields.cmd_sig_s_hash);
  pushFelt(args, fields.command_auth_hash);
  pushFelt(args, fields.signature_valid);
}

function pushNativeProcessDeactivateSignatureWitness(args, witness) {
  pushVector2(args, witness.pub_key);
  pushVector2(args, witness.r8);
  pushU256(args, witness.s);
  pushVector3(args, witness.packed_cmd);
  pushU256(args, witness.cmd_salt);
}

function pushNativeProcessDeactivateDecryptFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.decrypt_kind);
  pushFelt(args, fields.coord_priv_key_hash);
  pushFelt(args, fields.c1_hash);
  pushFelt(args, fields.c2_hash);
  pushFelt(args, fields.decrypt_is_odd);
  pushFelt(args, fields.decrypt_binding_hash);
}

function pushNativeProcessDeactivateDecryptWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.c1);
  pushVector2(args, witness.c2);
  pushVector2(args, witness.decrypted_point);
}

function pushNativeProcessDeactivateStepCoreFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.deactivate_index);
  pushFelt(args, fields.coord_priv_key_hash);
  pushFelt(args, fields.previous_message_hash);
  pushFelt(args, fields.next_message_hash);
  pushFelt(args, fields.current_active_state_root_hash);
  pushFelt(args, fields.current_deactivate_root_hash);
  pushFelt(args, fields.new_active_state_root_hash);
  pushFelt(args, fields.new_deactivate_root_hash);
  pushFelt(args, fields.current_deactivate_commitment_hash);
  pushFelt(args, fields.new_deactivate_commitment_hash);
  pushFelt(args, fields.current_state_root_hash);
  pushFelt(args, fields.expected_poll_id);
  pushFelt(args, fields.enc_pub_key_hash);
  pushFelt(args, fields.command_shared_key_hash);
  pushFelt(args, fields.command_shared_key_binding_hash);
  pushFelt(args, fields.signature_pub_key_hash);
  pushFelt(args, fields.signature_r8_hash);
  pushFelt(args, fields.packed_cmd_hash);
  pushFelt(args, fields.cmd_sig_s_hash);
  pushFelt(args, fields.command_auth_hash);
  pushFelt(args, fields.command_plaintext_binding_hash);
  pushFelt(args, fields.signature_valid);
  pushFelt(args, fields.current_state_ciphertext_c1_hash);
  pushFelt(args, fields.current_state_ciphertext_c2_hash);
  pushFelt(args, fields.current_decrypt_is_odd);
  pushFelt(args, fields.current_decrypt_binding_hash);
  pushFelt(args, fields.new_state_ciphertext_c1_hash);
  pushFelt(args, fields.new_state_ciphertext_c2_hash);
  pushFelt(args, fields.new_decrypt_is_odd);
  pushFelt(args, fields.new_decrypt_binding_hash);
  pushFelt(args, fields.deactivate_pub_key_hash);
  pushFelt(args, fields.deactivate_shared_key_hash);
  pushFelt(args, fields.deactivate_shared_key_binding_hash);
}

function pushNativeProcessDeactivateStepCoreWitness(args, witness) {
  pushU256(args, witness.is_empty_msg);
  pushU256(args, witness.coord_priv_key);
  pushVector10(args, witness.msg);
  pushVector2(args, witness.enc_pub_key);
  pushVector2(args, witness.command_shared_key);
  pushVector7(args, witness.decrypted_command);
  pushVector2(args, witness.c1);
  pushVector2(args, witness.c2);
  pushVector10(args, witness.state_leaf);
  pushVector2(args, witness.current_decrypted_point);
  pushVector2(args, witness.new_decrypted_point);
  pushVector4(args, witness.state_leaf_path_0);
  pushVector4(args, witness.state_leaf_path_1);
  pushVector4(args, witness.active_state_leaf_path_0);
  pushVector4(args, witness.active_state_leaf_path_1);
  pushU256(args, witness.current_active_state);
  pushU256(args, witness.new_active_state);
  pushU256(args, witness.cmd_state_index);
  pushU256(args, witness.cmd_poll_id);
  pushVector2(args, witness.cmd_sig_r8);
  pushU256(args, witness.cmd_sig_s);
  pushVector3(args, witness.packed_cmd);
  pushVector4(args, witness.deactivate_leaf_path_0);
  pushVector4(args, witness.deactivate_leaf_path_1);
  pushVector4(args, witness.deactivate_leaf_path_2);
  pushVector4(args, witness.deactivate_leaf_path_3);
  pushU256(args, witness.current_decrypt_is_odd);
  pushU256(args, witness.new_decrypt_is_odd);
  pushU256(args, witness.signature_valid);
  pushVector2(args, witness.deactivate_shared_key);
}

export function serializeNativeCairoProcessDeactivateCoordKeyExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessDeactivateCoordKeyFields(args, cairoInput.program_input.fields);
  pushNativeProcessDeactivateCoordKeyWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessDeactivateEcdhExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessDeactivateEcdhFields(args, cairoInput.program_input.fields);
  pushNativeProcessDeactivateEcdhWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessDeactivateSignatureExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessDeactivateSignatureFields(args, cairoInput.program_input.fields);
  pushNativeProcessDeactivateSignatureWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessDeactivateDecryptExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessDeactivateDecryptFields(args, cairoInput.program_input.fields);
  pushNativeProcessDeactivateDecryptWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessDeactivateStepCoreExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessDeactivateStepCoreFields(args, cairoInput.program_input.fields);
  pushNativeProcessDeactivateStepCoreWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessDeactivateStageExecutableArgs(cairoInput) {
  const args = [];
  const { boundary, coordKey, messages } = cairoInput.components;

  args.push(...serializeNativeCairoProcessDeactivateBoundaryExecutableArgs(boundary));
  args.push(...serializeNativeCairoProcessDeactivateCoordKeyExecutableArgs(coordKey));

  for (const message of messages) {
    args.push(...serializeNativeCairoProcessDeactivateEcdhExecutableArgs(message.commandEcdh));
    args.push(...serializeNativeCairoProcessDeactivateEcdhExecutableArgs(message.leafEcdh));
    args.push(...serializeNativeCairoProcessDeactivateSignatureExecutableArgs(message.signature));
    args.push(...serializeNativeCairoProcessDeactivateDecryptExecutableArgs(message.currentDecrypt));
    args.push(...serializeNativeCairoProcessDeactivateDecryptExecutableArgs(message.newDecrypt));
    args.push(...serializeNativeCairoProcessDeactivateStepCoreExecutableArgs(message.core));
  }

  return args;
}
