import { bigintToHex, decimalize, splitU256ToU128 } from '../compat/encoding.mjs';
import {
  NATIVE_PUBLIC_OUTPUT_VERSION,
  PROCESS_DEACTIVATE_COORD_KEY_NATIVE_CIRCUIT_ID,
  PROCESS_DEACTIVATE_DECRYPT_NATIVE_CIRCUIT_ID,
  PROCESS_DEACTIVATE_ECDH_NATIVE_CIRCUIT_ID,
  PROCESS_DEACTIVATE_SIGNATURE_NATIVE_CIRCUIT_ID,
  PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
  PUBLIC_OUTPUT_MAGIC,
  STARKNET_POSEIDON_HASH_SCHEME,
} from '../constants.mjs';
import { poseidonManyFelts } from '../integrity/hashes.mjs';
import {
  buildCairoBabyjubPoseidonSignatureInput,
  buildCairoBabyjubScalarMulInput,
} from '../compat/babyjub-cairo-input.mjs';
import { BABYJUB_BASE8 } from '../compat/babyjub.mjs';
import { hash5, hash13, hashLeftRight } from '../compat/poseidon.mjs';
import {
  canonicalProcessDeactivateCoordKeyPublicOutput,
  canonicalProcessDeactivateDecryptPublicOutput,
  canonicalProcessDeactivateEcdhPublicOutput,
  canonicalProcessDeactivateSignaturePublicOutput,
  canonicalProcessDeactivateStepCorePublicOutput,
  canonicalProcessDeactivateStepPublicOutput,
} from '../public-output.mjs';
import {
  evaluateProcessDeactivateMessages,
  evaluateProcessDeactivateMessagesStateTransition,
  evaluateProcessDeactivateMessagesStateful,
  processDeactivateMessageHash,
} from './process-deactivate-messages.mjs';
import { poseidonDecryptWithoutCheck7 } from '../msg/process-one.mjs';
import { evaluateProcessDeactivateOne } from './process-deactivate-one.mjs';

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

function u256Limbs(value, label) {
  const { low, high } = splitU256ToU128(value, label);
  return [low, high];
}

function nativeHashU256(value, label) {
  return poseidonManyFelts(u256Limbs(value, label));
}

function nativeHashPoint(values, label) {
  if (!Array.isArray(values) || values.length !== 2) {
    throw new Error(`${label} must contain two values`);
  }
  return poseidonManyFelts([
    ...u256Limbs(values[0], `${label}[0]`),
    ...u256Limbs(values[1], `${label}[1]`),
  ]);
}

function nativeCoordPrivKeyHash(coordPrivKey) {
  return poseidonManyFelts([
    ...u256Limbs(coordPrivKey, 'coordPrivKey'),
    PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
  ]);
}

function nativePackedCmdHash(packedCmd) {
  if (!Array.isArray(packedCmd) || packedCmd.length !== 3) {
    throw new Error('packedCmd must contain three values');
  }
  return poseidonManyFelts([
    ...u256Limbs(packedCmd[0], 'packedCmd[0]'),
    ...u256Limbs(packedCmd[1], 'packedCmd[1]'),
    ...u256Limbs(packedCmd[2], 'packedCmd[2]'),
  ]);
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

function splitVector5(values, label) {
  if (!Array.isArray(values) || values.length !== 5) {
    throw new Error(`${label} must contain five values`);
  }
  return {
    v0: splitObject(values[0], `${label}[0]`),
    v1: splitObject(values[1], `${label}[1]`),
    v2: splitObject(values[2], `${label}[2]`),
    v3: splitObject(values[3], `${label}[3]`),
    v4: splitObject(values[4], `${label}[4]`),
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

function hash2Claim(in0, in1, out, label) {
  return {
    in0: splitObject(in0, `${label}.in0`),
    in1: splitObject(in1, `${label}.in1`),
    out: splitObject(out, `${label}.out`),
  };
}

function hash5Claim(inputs, out, label) {
  return {
    inputs: splitVector5(inputs, `${label}.inputs`),
    out: splitObject(out, `${label}.out`),
  };
}

function hash10Claim(inputs, out, label) {
  const firstInputs = inputs.slice(0, 5);
  const secondInputs = inputs.slice(5, 10);
  const firstHash = hash5(firstInputs);
  const secondHash = hash5(secondInputs);
  const expectedOut = hashLeftRight(firstHash, secondHash);
  if (expectedOut !== BigInt(out)) {
    throw new Error(`${label}.out mismatch`);
  }
  return {
    first: hash5Claim(firstInputs, firstHash, `${label}.first`),
    second: hash5Claim(secondInputs, secondHash, `${label}.second`),
    out: hash2Claim(firstHash, secondHash, out, `${label}.out`),
  };
}

function hash13Claim(inputs, out, label) {
  if (!Array.isArray(inputs) || inputs.length !== 13) {
    throw new Error(`${label}.inputs must contain thirteen values`);
  }
  const firstInputs = inputs.slice(0, 5);
  const secondInputs = inputs.slice(5, 10);
  const firstHash = hash5(firstInputs);
  const secondHash = hash5(secondInputs);
  const finalInputs = [firstHash, secondHash, inputs[10], inputs[11], inputs[12]];
  const expectedOut = hash13(inputs);
  if (expectedOut !== BigInt(out)) {
    throw new Error(`${label}.out mismatch`);
  }
  return {
    first: hash5Claim(firstInputs, firstHash, `${label}.first`),
    second: hash5Claim(secondInputs, secondHash, `${label}.second`),
    out: hash5Claim(finalInputs, out, `${label}.out`),
  };
}

function sha256U256x8Claim(inputs, out, label) {
  return {
    inputs: {
      v0: splitObject(inputs[0], `${label}.inputs[0]`),
      v1: splitObject(inputs[1], `${label}.inputs[1]`),
      v2: splitObject(inputs[2], `${label}.inputs[2]`),
      v3: splitObject(inputs[3], `${label}.inputs[3]`),
      v4: splitObject(inputs[4], `${label}.inputs[4]`),
      v5: splitObject(inputs[5], `${label}.inputs[5]`),
      v6: splitObject(inputs[6], `${label}.inputs[6]`),
      v7: splitObject(inputs[7], `${label}.inputs[7]`),
    },
    out: splitObject(out, `${label}.out`),
  };
}

function pointsEqual(left, right) {
  return left[0] === right[0] && left[1] === right[1];
}

function coordPrivKeyHash(coordPrivKey) {
  return hashLeftRight(BigInt(coordPrivKey), PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN);
}

function packedCmdHash(packedCmd) {
  return hash5([packedCmd[0], packedCmd[1], packedCmd[2], 0n, 0n]);
}

function pointHash(point) {
  return hashLeftRight(point[0], point[1]);
}

function buildElGamalDecryptWitness(result, c1, decrypt, label) {
  const scalarMulInput = buildCairoBabyjubScalarMulInput({
    scalar: result.input.coordPrivKey,
    base: c1,
  });
  if (!pointsEqual(scalarMulInput.expected, decrypt.c1x)) {
    throw new Error(`${label} scalar multiplication does not match decrypt transcript`);
  }
  return {
    scalar_mul: scalarMulInput.program_input.witness,
    decrypted_point: splitVector2(decrypt.decryptedPoint, `${label}.decryptedPoint`),
  };
}

function buildProcessDeactivateOneWitness(result) {
  const { input, derived } = result;
  const signatureInput = buildCairoBabyjubPoseidonSignatureInput({
    pubKey: input.stateLeaf.slice(0, 2),
    r8: input.cmdSigR8,
    s: input.cmdSigS,
    preimage: input.packedCmd,
  });
  if (signatureInput.valid !== derived.signatureValid) {
    throw new Error('signature verification result does not match ProcessDeactivate witness');
  }

  const deactivateEcdh = buildCairoBabyjubScalarMulInput({
    scalar: input.coordPrivKey,
    base: input.stateLeaf.slice(0, 2),
  });
  if (!pointsEqual(deactivateEcdh.expected, derived.sharedKey)) {
    throw new Error('deactivate ECDH shared key does not match ProcessDeactivate witness');
  }

  return {
    is_empty_msg: splitObject(input.isEmptyMsg, 'isEmptyMsg'),
    coord_priv_key: splitObject(input.coordPrivKey, 'coordPrivKey'),
    current_state_root: splitObject(input.currentStateRoot, 'currentStateRoot'),
    c1: splitVector2(input.c1, 'c1'),
    c2: splitVector2(input.c2, 'c2'),
    current_active_state_root: splitObject(input.currentActiveStateRoot, 'currentActiveStateRoot'),
    current_deactivate_root: splitObject(input.currentDeactivateRoot, 'currentDeactivateRoot'),
    state_leaf: splitVector10(input.stateLeaf, 'stateLeaf'),
    state_leaf_path_0: splitVector4(input.stateLeafPathElements[0], 'stateLeafPathElements[0]'),
    state_leaf_path_1: splitVector4(input.stateLeafPathElements[1], 'stateLeafPathElements[1]'),
    active_state_leaf_path_0: splitVector4(
      input.activeStateLeafPathElements[0],
      'activeStateLeafPathElements[0]',
    ),
    active_state_leaf_path_1: splitVector4(
      input.activeStateLeafPathElements[1],
      'activeStateLeafPathElements[1]',
    ),
    current_active_state: splitObject(input.currentActiveState, 'currentActiveState'),
    new_active_state: splitObject(input.newActiveState, 'newActiveState'),
    cmd_state_index: splitObject(input.cmdStateIndex, 'cmdStateIndex'),
    cmd_poll_id: splitObject(input.cmdPollId, 'cmdPollId'),
    cmd_sig_r8: splitVector2(input.cmdSigR8, 'cmdSigR8'),
    cmd_sig_s: splitObject(input.cmdSigS, 'cmdSigS'),
    packed_cmd: splitVector3(input.packedCmd, 'packedCmd'),
    expected_poll_id: splitObject(input.expectedPollId, 'expectedPollId'),
    deactivate_index: splitObject(input.deactivateIndex, 'deactivateIndex'),
    deactivate_leaf_path_0: splitVector4(
      input.deactivateLeafPathElements[0],
      'deactivateLeafPathElements[0]',
    ),
    deactivate_leaf_path_1: splitVector4(
      input.deactivateLeafPathElements[1],
      'deactivateLeafPathElements[1]',
    ),
    deactivate_leaf_path_2: splitVector4(
      input.deactivateLeafPathElements[2],
      'deactivateLeafPathElements[2]',
    ),
    deactivate_leaf_path_3: splitVector4(
      input.deactivateLeafPathElements[3],
      'deactivateLeafPathElements[3]',
    ),
    current_state_decrypt: buildElGamalDecryptWitness(
      result,
      input.stateLeaf.slice(5, 7),
      derived.currentStateDecrypt,
      'currentStateDecrypt',
    ),
    new_state_decrypt: buildElGamalDecryptWitness(
      result,
      input.c1,
      derived.newStateDecrypt,
      'newStateDecrypt',
    ),
    deactivate_ecdh: deactivateEcdh.program_input.witness,
    signature: signatureInput.program_input.witness,
    hashes: {
      state_leaf_hash: hash10Claim(input.stateLeaf, derived.stateLeafHash, 'stateLeafHash'),
      shared_key_hash: hash2Claim(
        derived.sharedKey[0],
        derived.sharedKey[1],
        derived.sharedKeyHash,
        'sharedKeyHash',
      ),
      deactivate_leaf: hash5Claim(
        [...input.c1, ...input.c2, derived.sharedKeyHash],
        derived.deactivateLeaf,
        'deactivateLeaf',
      ),
    },
  };
}

export function buildCairoProcessDeactivateOneInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessDeactivateOne(rawInput);
  return {
    program_input: {
      witness: buildProcessDeactivateOneWitness(result),
    },
    expected_output: {
      new_active_state_root: splitObject(result.derived.newActiveStateRoot, 'newActiveStateRoot'),
      new_deactivate_root: splitObject(result.derived.newDeactivateRoot, 'newDeactivateRoot'),
    },
    full_witness: rawInput,
  };
}

function deactivateMessagePreimage(message, encPubKey, prevHash) {
  return [
    ...message.map(BigInt),
    BigInt(encPubKey[0]),
    BigInt(encPubKey[1]),
    BigInt(prevHash),
  ];
}

function buildDeactivateMessageHashClaims(rawInput) {
  const claims = [];
  let prevHash = BigInt(rawInput.batchStartHash);
  for (let i = 0; i < 5; i += 1) {
    const preimage = deactivateMessagePreimage(rawInput.msgs[i], rawInput.encPubKeys[i], prevHash);
    const messageHash = processDeactivateMessageHash(rawInput.msgs[i], rawInput.encPubKeys[i], prevHash);
    claims.push(hash13Claim(preimage, messageHash, `deactivateMessageHash${i}`));
    prevHash = BigInt(rawInput.msgs[i][0]) === 0n ? prevHash : messageHash;
  }
  return claims;
}

function buildCairoProcessDeactivateMessagesBoundaryWitness(rawInput, evaluated) {
  const messageHashClaims = buildDeactivateMessageHashClaims(rawInput);
  return {
    coord_pub_key: splitVector2(rawInput.coordPubKey, 'coordPubKey'),
    current_active_state_root: splitObject(
      rawInput.currentActiveStateRoot,
      'currentActiveStateRoot',
    ),
    current_deactivate_root: splitObject(rawInput.currentDeactivateRoot, 'currentDeactivateRoot'),
    batch_start_hash: splitObject(rawInput.batchStartHash, 'batchStartHash'),
    batch_end_hash: splitObject(rawInput.batchEndHash, 'batchEndHash'),
    current_state_root: splitObject(rawInput.currentStateRoot, 'currentStateRoot'),
    expected_poll_id: splitObject(rawInput.expectedPollId, 'expectedPollId'),
    msg_0: splitVector10(rawInput.msgs[0], 'msgs[0]'),
    msg_1: splitVector10(rawInput.msgs[1], 'msgs[1]'),
    msg_2: splitVector10(rawInput.msgs[2], 'msgs[2]'),
    msg_3: splitVector10(rawInput.msgs[3], 'msgs[3]'),
    msg_4: splitVector10(rawInput.msgs[4], 'msgs[4]'),
    enc_pub_key_0: splitVector2(rawInput.encPubKeys[0], 'encPubKeys[0]'),
    enc_pub_key_1: splitVector2(rawInput.encPubKeys[1], 'encPubKeys[1]'),
    enc_pub_key_2: splitVector2(rawInput.encPubKeys[2], 'encPubKeys[2]'),
    enc_pub_key_3: splitVector2(rawInput.encPubKeys[3], 'encPubKeys[3]'),
    enc_pub_key_4: splitVector2(rawInput.encPubKeys[4], 'encPubKeys[4]'),
    hashes: {
      coord_pub_key_hash: hash2Claim(
        rawInput.coordPubKey[0],
        rawInput.coordPubKey[1],
        evaluated.publicFields.coordPubKeyHash,
        'coordPubKeyHash',
      ),
      input_hash: sha256U256x8Claim(
        [
          evaluated.publicFields.newDeactivateRoot,
          evaluated.publicFields.coordPubKeyHash,
          evaluated.publicFields.batchStartHash,
          evaluated.publicFields.batchEndHash,
          evaluated.publicFields.currentDeactivateCommitment,
          evaluated.publicFields.newDeactivateCommitment,
          evaluated.publicFields.currentStateRoot,
          evaluated.publicFields.expectedPollId,
        ],
        evaluated.publicFields.inputHash,
        'inputHash',
      ),
      current_deactivate_commitment: hash2Claim(
        rawInput.currentActiveStateRoot,
        rawInput.currentDeactivateRoot,
        evaluated.publicFields.currentDeactivateCommitment,
        'currentDeactivateCommitment',
      ),
      message_hash_0: messageHashClaims[0],
      message_hash_1: messageHashClaims[1],
      message_hash_2: messageHashClaims[2],
      message_hash_3: messageHashClaims[3],
      message_hash_4: messageHashClaims[4],
    },
  };
}

export function buildCairoProcessDeactivateMessagesBoundaryInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessDeactivateMessages(rawInput);
  const fields = {
    new_deactivate_root: splitObject(result.publicFields.newDeactivateRoot, 'newDeactivateRoot'),
    coord_pub_key_hash: splitObject(result.publicFields.coordPubKeyHash, 'coordPubKeyHash'),
    batch_start_hash: splitObject(result.publicFields.batchStartHash, 'batchStartHash'),
    batch_end_hash: splitObject(result.publicFields.batchEndHash, 'batchEndHash'),
    current_deactivate_commitment: splitObject(
      result.publicFields.currentDeactivateCommitment,
      'currentDeactivateCommitment',
    ),
    new_deactivate_commitment: splitObject(
      result.publicFields.newDeactivateCommitment,
      'newDeactivateCommitment',
    ),
    current_state_root: splitObject(result.publicFields.currentStateRoot, 'currentStateRoot'),
    expected_poll_id: splitObject(result.publicFields.expectedPollId, 'expectedPollId'),
    input_hash: splitObject(result.publicFields.inputHash, 'inputHash'),
  };

  return {
    fields,
    program_input: {
      fields,
      witness: buildCairoProcessDeactivateMessagesBoundaryWitness(rawInput, result),
    },
    full_witness: rawInput,
    public_output: result.publicOutput.decimalFelts,
  };
}

function buildProcessDeactivateMessagesStateTransitionWitness(result) {
  return {
    coord_priv_key: splitObject(result.input.coordPrivKey, 'coordPrivKey'),
    current_state_root: splitObject(result.input.currentStateRoot, 'currentStateRoot'),
    current_active_state_root: splitObject(result.input.currentActiveStateRoot, 'currentActiveStateRoot'),
    current_deactivate_root: splitObject(result.input.currentDeactivateRoot, 'currentDeactivateRoot'),
    expected_poll_id: splitObject(result.input.expectedPollId, 'expectedPollId'),
    deactivate_index_0: splitObject(result.input.deactivateIndex0, 'deactivateIndex0'),
    process_one_0: buildProcessDeactivateOneWitness(result.transitions[0]),
    process_one_1: buildProcessDeactivateOneWitness(result.transitions[1]),
    process_one_2: buildProcessDeactivateOneWitness(result.transitions[2]),
    process_one_3: buildProcessDeactivateOneWitness(result.transitions[3]),
    process_one_4: buildProcessDeactivateOneWitness(result.transitions[4]),
  };
}

export function buildCairoProcessDeactivateMessagesStateTransitionInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateTransition(rawInput);
  return {
    program_input: {
      witness: buildProcessDeactivateMessagesStateTransitionWitness(result),
    },
    expected_output: {
      new_active_state_root: splitObject(result.derived.newActiveStateRoot, 'newActiveStateRoot'),
      new_deactivate_root: splitObject(result.derived.newDeactivateRoot, 'newDeactivateRoot'),
    },
    full_witness: rawInput,
  };
}

function buildCairoCoordPubKeyWitness(rawInput, stateResult) {
  const coordPubKeyInput = buildCairoBabyjubScalarMulInput({
    scalar: stateResult.input.coordPrivKey,
    base: BABYJUB_BASE8.map((value) => value.toString()),
  });
  if (!pointsEqual(coordPubKeyInput.expected, stateResult.input.coordPubKey ?? [])) {
    const boundaryCoordPubKey = rawInput.coordPubKey.map(BigInt);
    if (!pointsEqual(coordPubKeyInput.expected, boundaryCoordPubKey)) {
      throw new Error('coordPrivKey does not match ProcessDeactivate coordPubKey');
    }
  }
  return coordPubKeyInput.program_input.witness;
}

function buildCairoProcessDeactivateMessageCommandWitness(rawInput, stateResult, messageIndex) {
  const msg = rawInput.msgs[messageIndex];
  const empty = BigInt(msg[0]) === 0n;
  const base = empty ? BABYJUB_BASE8.map((value) => value.toString()) : rawInput.encPubKeys[messageIndex];
  const ecdhInput = buildCairoBabyjubScalarMulInput({
    scalar: stateResult.input.coordPrivKey,
    base,
  });
  const decryptedCommand = empty
    ? Array.from({ length: 7 }, () => 0n)
    : poseidonDecryptWithoutCheck7(msg, ecdhInput.expected);
  if (!empty) {
    const processOne = stateResult.transitions[messageIndex].input;
    if (
      decryptedCommand[0] !== processOne.packedCmd[0] ||
      decryptedCommand[1] !== processOne.packedCmd[1] ||
      decryptedCommand[2] !== processOne.packedCmd[2] ||
      decryptedCommand[4] !== processOne.cmdSigR8[0] ||
      decryptedCommand[5] !== processOne.cmdSigR8[1] ||
      decryptedCommand[6] !== processOne.cmdSigS
    ) {
      throw new Error(`decrypted deactivate command ${messageIndex} does not match ProcessOne witness`);
    }
  }
  return {
    ecdh: ecdhInput.program_input.witness,
    decrypted_command: {
      v0: splitObject(decryptedCommand[0], `decryptedCommand[${messageIndex}][0]`),
      v1: splitObject(decryptedCommand[1], `decryptedCommand[${messageIndex}][1]`),
      v2: splitObject(decryptedCommand[2], `decryptedCommand[${messageIndex}][2]`),
      v3: splitObject(decryptedCommand[3], `decryptedCommand[${messageIndex}][3]`),
      v4: splitObject(decryptedCommand[4], `decryptedCommand[${messageIndex}][4]`),
      v5: splitObject(decryptedCommand[5], `decryptedCommand[${messageIndex}][5]`),
      v6: splitObject(decryptedCommand[6], `decryptedCommand[${messageIndex}][6]`),
    },
  };
}

export function buildCairoProcessDeactivateMessagesStatefulInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const boundaryInput = buildCairoProcessDeactivateMessagesBoundaryInput(rawInput, result.boundary);
  const stateInput = buildCairoProcessDeactivateMessagesStateTransitionInput(rawInput, result.state);
  return {
    fields: boundaryInput.fields,
    program_input: {
      fields: boundaryInput.program_input.fields,
      witness: {
        boundary: boundaryInput.program_input.witness,
        state_transition: stateInput.program_input.witness,
        coord_pub_key: buildCairoCoordPubKeyWitness(rawInput, result.state),
        command_0: buildCairoProcessDeactivateMessageCommandWitness(rawInput, result.state, 0),
        command_1: buildCairoProcessDeactivateMessageCommandWitness(rawInput, result.state, 1),
        command_2: buildCairoProcessDeactivateMessageCommandWitness(rawInput, result.state, 2),
        command_3: buildCairoProcessDeactivateMessageCommandWitness(rawInput, result.state, 3),
        command_4: buildCairoProcessDeactivateMessageCommandWitness(rawInput, result.state, 4),
        new_deactivate_commitment: hash2Claim(
          result.derived.newActiveStateRoot,
          result.derived.newDeactivateRoot,
          result.derived.newDeactivateCommitment,
          'newDeactivateCommitment',
        ),
      },
    },
    full_witness: rawInput,
    public_output: result.publicOutput.decimalFelts,
  };
}

function assertMessageIndex(messageIndex) {
  if (!Number.isInteger(messageIndex) || messageIndex < 0 || messageIndex >= 5) {
    throw new Error('messageIndex must be an integer in [0, 4]');
  }
}

export function buildCairoProcessDeactivateMessageStepInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const currentDeactivateCommitment = hashLeftRight(
    transition.input.currentActiveStateRoot,
    transition.input.currentDeactivateRoot,
  );
  const newDeactivateCommitment = hashLeftRight(
    transition.derived.newActiveStateRoot,
    transition.derived.newDeactivateRoot,
  );
  const publicFields = {
    messageIndex: BigInt(messageIndex),
    deactivateIndex: transition.input.deactivateIndex,
    coordPubKeyHash: result.publicFields.coordPubKeyHash,
    previousMessageHash: result.boundary.derived.messageHashChain[messageIndex],
    nextMessageHash: result.boundary.derived.messageHashChain[messageIndex + 1],
    currentActiveStateRoot: transition.input.currentActiveStateRoot,
    currentDeactivateRoot: transition.input.currentDeactivateRoot,
    newActiveStateRoot: transition.derived.newActiveStateRoot,
    newDeactivateRoot: transition.derived.newDeactivateRoot,
    currentDeactivateCommitment,
    newDeactivateCommitment,
    currentStateRoot: result.publicFields.currentStateRoot,
    expectedPollId: result.publicFields.expectedPollId,
  };
  const fields = {
    message_index: publicFields.messageIndex,
    deactivate_index: splitObject(publicFields.deactivateIndex, 'deactivateIndex'),
    coord_pub_key_hash: splitObject(publicFields.coordPubKeyHash, 'coordPubKeyHash'),
    previous_message_hash: splitObject(
      publicFields.previousMessageHash,
      'previousMessageHash',
    ),
    next_message_hash: splitObject(publicFields.nextMessageHash, 'nextMessageHash'),
    current_active_state_root: splitObject(
      publicFields.currentActiveStateRoot,
      'currentActiveStateRoot',
    ),
    current_deactivate_root: splitObject(
      publicFields.currentDeactivateRoot,
      'currentDeactivateRoot',
    ),
    new_active_state_root: splitObject(publicFields.newActiveStateRoot, 'newActiveStateRoot'),
    new_deactivate_root: splitObject(publicFields.newDeactivateRoot, 'newDeactivateRoot'),
    current_deactivate_commitment: splitObject(
      publicFields.currentDeactivateCommitment,
      'currentDeactivateCommitment',
    ),
    new_deactivate_commitment: splitObject(
      publicFields.newDeactivateCommitment,
      'newDeactivateCommitment',
    ),
    current_state_root: splitObject(publicFields.currentStateRoot, 'currentStateRoot'),
    expected_poll_id: splitObject(publicFields.expectedPollId, 'expectedPollId'),
  };
  const coordPubKeyInput = buildCairoBabyjubScalarMulInput({
    scalar: result.state.input.coordPrivKey,
    base: BABYJUB_BASE8.map((value) => value.toString()),
  });
  if (!pointsEqual(coordPubKeyInput.expected, rawInput.coordPubKey.map(BigInt))) {
    throw new Error('coordPrivKey does not match ProcessDeactivate coordPubKey');
  }
  const publicOutput = canonicalProcessDeactivateStepPublicOutput(publicFields, result.params);

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        coord_pub_key: splitVector2(rawInput.coordPubKey, 'coordPubKey'),
        msg: splitVector10(rawInput.msgs[messageIndex], 'msg'),
        enc_pub_key: splitVector2(rawInput.encPubKeys[messageIndex], 'encPubKey'),
        coord_priv_key: splitObject(result.state.input.coordPrivKey, 'coordPrivKey'),
        coord_pub_key_scalar_mul: coordPubKeyInput.program_input.witness,
        coord_pub_key_hash: hash2Claim(
          rawInput.coordPubKey[0],
          rawInput.coordPubKey[1],
          publicFields.coordPubKeyHash,
          'coordPubKeyHash',
        ),
        message_hash: hash13Claim(
          deactivateMessagePreimage(
            rawInput.msgs[messageIndex],
            rawInput.encPubKeys[messageIndex],
            publicFields.previousMessageHash,
          ),
          processDeactivateMessageHash(
            rawInput.msgs[messageIndex],
            rawInput.encPubKeys[messageIndex],
            publicFields.previousMessageHash,
          ),
          `deactivateMessageHash${messageIndex}`,
        ),
        command: buildCairoProcessDeactivateMessageCommandWitness(
          rawInput,
          result.state,
          messageIndex,
        ),
        process_one: buildProcessDeactivateOneWitness(transition),
        current_deactivate_commitment: hash2Claim(
          publicFields.currentActiveStateRoot,
          publicFields.currentDeactivateRoot,
          publicFields.currentDeactivateCommitment,
          'currentDeactivateCommitment',
        ),
        new_deactivate_commitment: hash2Claim(
          publicFields.newActiveStateRoot,
          publicFields.newDeactivateRoot,
          publicFields.newDeactivateCommitment,
          'newDeactivateCommitment',
        ),
      },
    },
    full_witness: {
      processDeactivate: rawInput,
      messageIndex,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

function isEmptyDeactivateMessage(rawInput, messageIndex) {
  return BigInt(rawInput.msgs[messageIndex][0]) === 0n;
}

function deactivateStepLinkFields(rawInput, messageIndex, result) {
  const transition = result.state.transitions[messageIndex];
  const command = result.derived.messageCommands[messageIndex];
  if (!command) {
    throw new Error('deep split deactivate proofs are not generated for empty message slots');
  }
  const input = transition.input;
  return {
    coordPrivKeyHash: coordPrivKeyHash(result.state.input.coordPrivKey),
    encPubKeyHash: pointHash(rawInput.encPubKeys[messageIndex].map(BigInt)),
    commandSharedKeyHash: pointHash(command.sharedKey),
    signaturePubKeyHash: pointHash(input.stateLeaf.slice(0, 2)),
    signatureR8Hash: pointHash(input.cmdSigR8),
    packedCmdHash: packedCmdHash(input.packedCmd),
    cmdSigS: input.cmdSigS,
    signatureValid: transition.derived.signatureValid,
    currentStateCiphertextC1Hash: pointHash(input.stateLeaf.slice(5, 7)),
    currentStateCiphertextC2Hash: pointHash(input.stateLeaf.slice(7, 9)),
    currentDecryptIsOdd: transition.derived.currentStateDecrypt.isOdd,
    newStateCiphertextC1Hash: pointHash(input.c1),
    newStateCiphertextC2Hash: pointHash(input.c2),
    newDecryptIsOdd: transition.derived.newStateDecrypt.isOdd,
    deactivatePubKeyHash: pointHash(input.stateLeaf.slice(0, 2)),
    deactivateSharedKeyHash: transition.derived.sharedKeyHash,
  };
}

export function buildCairoProcessDeactivateCoordKeyInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const coordPubKeyInput = buildCairoBabyjubScalarMulInput({
    scalar: result.state.input.coordPrivKey,
    base: BABYJUB_BASE8.map((value) => value.toString()),
  });
  if (!pointsEqual(coordPubKeyInput.expected, rawInput.coordPubKey.map(BigInt))) {
    throw new Error('coordPrivKey does not match ProcessDeactivate coordPubKey');
  }
  const publicFields = {
    coordPubKeyHash: result.publicFields.coordPubKeyHash,
    coordPrivKeyHash: coordPrivKeyHash(result.state.input.coordPrivKey),
  };
  const fields = {
    coord_pub_key_hash: splitObject(publicFields.coordPubKeyHash, 'coordPubKeyHash'),
    coord_priv_key_hash: splitObject(publicFields.coordPrivKeyHash, 'coordPrivKeyHash'),
  };
  const publicOutput = canonicalProcessDeactivateCoordKeyPublicOutput(publicFields, result.params);

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        coord_priv_key: splitObject(result.state.input.coordPrivKey, 'coordPrivKey'),
        coord_pub_key: splitVector2(rawInput.coordPubKey, 'coordPubKey'),
        coord_pub_key_scalar_mul: coordPubKeyInput.program_input.witness,
        coord_pub_key_hash: hash2Claim(
          rawInput.coordPubKey[0],
          rawInput.coordPubKey[1],
          publicFields.coordPubKeyHash,
          'coordPubKeyHash',
        ),
        coord_priv_key_hash: hash2Claim(
          result.state.input.coordPrivKey,
          PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
          publicFields.coordPrivKeyHash,
          'coordPrivKeyHash',
        ),
      },
    },
    full_witness: {
      processDeactivate: rawInput,
      coordPubKey: coordPubKeyInput.full_witness,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildCairoProcessDeactivateEcdhInput(
  rawInput,
  messageIndex,
  ecdhKind = 'command',
  evaluated,
) {
  assertMessageIndex(messageIndex);
  if (isEmptyDeactivateMessage(rawInput, messageIndex)) {
    throw new Error('cannot build deactivate ECDH proof for an empty message slot');
  }
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const command = result.derived.messageCommands[messageIndex];
  const kind = ecdhKind === 'leaf' ? 1n : 0n;
  const base = ecdhKind === 'leaf'
    ? transition.input.stateLeaf.slice(0, 2)
    : rawInput.encPubKeys[messageIndex].map(BigInt);
  const expectedSharedKey = ecdhKind === 'leaf' ? transition.derived.sharedKey : command.sharedKey;
  const ecdhInput = buildCairoBabyjubScalarMulInput({
    scalar: result.state.input.coordPrivKey,
    base,
  });
  if (!pointsEqual(ecdhInput.expected, expectedSharedKey)) {
    throw new Error(`deactivate ${ecdhKind} ECDH shared key mismatch at message ${messageIndex}`);
  }
  const publicFields = {
    messageIndex: BigInt(messageIndex),
    ecdhKind: kind,
    coordPrivKeyHash: coordPrivKeyHash(result.state.input.coordPrivKey),
    baseHash: pointHash(base),
    sharedKeyHash: pointHash(expectedSharedKey),
  };
  const fields = {
    message_index: publicFields.messageIndex,
    ecdh_kind: publicFields.ecdhKind,
    coord_priv_key_hash: splitObject(publicFields.coordPrivKeyHash, 'coordPrivKeyHash'),
    base_hash: splitObject(publicFields.baseHash, 'baseHash'),
    shared_key_hash: splitObject(publicFields.sharedKeyHash, 'sharedKeyHash'),
  };
  const publicOutput = canonicalProcessDeactivateEcdhPublicOutput(publicFields, result.params);

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        coord_priv_key: splitObject(result.state.input.coordPrivKey, 'coordPrivKey'),
        base: splitVector2(base, 'base'),
        ecdh: ecdhInput.program_input.witness,
        coord_priv_key_hash: hash2Claim(
          result.state.input.coordPrivKey,
          PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
          publicFields.coordPrivKeyHash,
          'coordPrivKeyHash',
        ),
        base_hash: hash2Claim(base[0], base[1], publicFields.baseHash, 'baseHash'),
        shared_key_hash: hash2Claim(
          expectedSharedKey[0],
          expectedSharedKey[1],
          publicFields.sharedKeyHash,
          'sharedKeyHash',
        ),
      },
    },
    full_witness: {
      processDeactivate: rawInput,
      messageIndex,
      ecdhKind,
      ecdh: ecdhInput.full_witness,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildCairoProcessDeactivateSignatureInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  if (isEmptyDeactivateMessage(rawInput, messageIndex)) {
    throw new Error('cannot build deactivate signature proof for an empty message slot');
  }
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const input = transition.input;
  const signatureInput = buildCairoBabyjubPoseidonSignatureInput({
    pubKey: input.stateLeaf.slice(0, 2),
    r8: input.cmdSigR8,
    s: input.cmdSigS,
    preimage: input.packedCmd,
  });
  if (signatureInput.valid !== transition.derived.signatureValid) {
    throw new Error('deactivate signature proof does not match transition signatureValid');
  }
  const publicFields = {
    messageIndex: BigInt(messageIndex),
    pubKeyHash: pointHash(input.stateLeaf.slice(0, 2)),
    r8Hash: pointHash(input.cmdSigR8),
    packedCmdHash: packedCmdHash(input.packedCmd),
    cmdSigS: input.cmdSigS,
    signatureValid: transition.derived.signatureValid,
  };
  const fields = {
    message_index: publicFields.messageIndex,
    pub_key_hash: splitObject(publicFields.pubKeyHash, 'pubKeyHash'),
    r8_hash: splitObject(publicFields.r8Hash, 'r8Hash'),
    packed_cmd_hash: splitObject(publicFields.packedCmdHash, 'packedCmdHash'),
    cmd_sig_s: splitObject(publicFields.cmdSigS, 'cmdSigS'),
    signature_valid: splitObject(publicFields.signatureValid, 'signatureValid'),
  };
  const publicOutput = canonicalProcessDeactivateSignaturePublicOutput(publicFields, result.params);

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
        signature: signatureInput.program_input.witness,
        pub_key_hash: hash2Claim(input.stateLeaf[0], input.stateLeaf[1], publicFields.pubKeyHash, 'pubKeyHash'),
        r8_hash: hash2Claim(input.cmdSigR8[0], input.cmdSigR8[1], publicFields.r8Hash, 'r8Hash'),
        packed_cmd_hash: hash5Claim(
          [input.packedCmd[0], input.packedCmd[1], input.packedCmd[2], 0n, 0n],
          publicFields.packedCmdHash,
          'packedCmdHash',
        ),
      },
    },
    full_witness: {
      processDeactivate: rawInput,
      messageIndex,
      signature: signatureInput.full_witness,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildCairoProcessDeactivateDecryptInput(
  rawInput,
  messageIndex,
  decryptKind = 'current',
  evaluated,
) {
  assertMessageIndex(messageIndex);
  if (isEmptyDeactivateMessage(rawInput, messageIndex)) {
    throw new Error('cannot build deactivate decrypt proof for an empty message slot');
  }
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const current = decryptKind === 'current';
  const c1 = current ? transition.input.stateLeaf.slice(5, 7) : transition.input.c1;
  const c2 = current ? transition.input.stateLeaf.slice(7, 9) : transition.input.c2;
  const decrypt = current ? transition.derived.currentStateDecrypt : transition.derived.newStateDecrypt;
  const decryptInput = buildElGamalDecryptWitness(
    transition,
    c1,
    decrypt,
    `${decryptKind}DeactivateDecrypt`,
  );
  const publicFields = {
    messageIndex: BigInt(messageIndex),
    decryptKind: current ? 0n : 1n,
    coordPrivKeyHash: coordPrivKeyHash(result.state.input.coordPrivKey),
    c1Hash: pointHash(c1),
    c2Hash: pointHash(c2),
    decryptIsOdd: decrypt.isOdd,
  };
  const fields = {
    message_index: publicFields.messageIndex,
    decrypt_kind: publicFields.decryptKind,
    coord_priv_key_hash: splitObject(publicFields.coordPrivKeyHash, 'coordPrivKeyHash'),
    c1_hash: splitObject(publicFields.c1Hash, 'c1Hash'),
    c2_hash: splitObject(publicFields.c2Hash, 'c2Hash'),
    decrypt_is_odd: splitObject(publicFields.decryptIsOdd, 'decryptIsOdd'),
  };
  const publicOutput = canonicalProcessDeactivateDecryptPublicOutput(publicFields, result.params);

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        coord_priv_key: splitObject(result.state.input.coordPrivKey, 'coordPrivKey'),
        c1: splitVector2(c1, 'c1'),
        c2: splitVector2(c2, 'c2'),
        decrypt: decryptInput,
        coord_priv_key_hash: hash2Claim(
          result.state.input.coordPrivKey,
          PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
          publicFields.coordPrivKeyHash,
          'coordPrivKeyHash',
        ),
        c1_hash: hash2Claim(c1[0], c1[1], publicFields.c1Hash, 'c1Hash'),
        c2_hash: hash2Claim(c2[0], c2[1], publicFields.c2Hash, 'c2Hash'),
      },
    },
    full_witness: {
      processDeactivate: rawInput,
      messageIndex,
      decryptKind,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessDeactivateCoordKeyInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const legacy = buildCairoProcessDeactivateCoordKeyInput(rawInput, result);
  const publicFields = {
    coord_pub_key_hash: nativeHashPoint(rawInput.coordPubKey, 'coordPubKey'),
    coord_priv_key_hash: nativeCoordPrivKeyHash(result.state.input.coordPrivKey),
  };
  const fields = {
    coord_pub_key_hash: feltObject(publicFields.coord_pub_key_hash),
    coord_priv_key_hash: feltObject(publicFields.coord_priv_key_hash),
  };
  const publicOutput = nativeProcessDeactivatePublicOutput(
    PROCESS_DEACTIVATE_COORD_KEY_NATIVE_CIRCUIT_ID,
    publicFields,
    result.params,
    ['coord_pub_key_hash', 'coord_priv_key_hash'],
  );

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: legacy.program_input.witness,
    },
    full_witness: legacy.full_witness,
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
  const legacy = buildCairoProcessDeactivateEcdhInput(rawInput, messageIndex, ecdhKind, result);
  const transition = result.state.transitions[messageIndex];
  const command = result.derived.messageCommands[messageIndex];
  const base = ecdhKind === 'leaf'
    ? transition.input.stateLeaf.slice(0, 2)
    : rawInput.encPubKeys[messageIndex].map(BigInt);
  const expectedSharedKey = ecdhKind === 'leaf' ? transition.derived.sharedKey : command.sharedKey;
  const publicFields = {
    message_index: BigInt(messageIndex),
    ecdh_kind: ecdhKind === 'leaf' ? 1n : 0n,
    coord_priv_key_hash: nativeCoordPrivKeyHash(result.state.input.coordPrivKey),
    base_hash: nativeHashPoint(base, 'base'),
    shared_key_hash: nativeHashPoint(expectedSharedKey, 'sharedKey'),
  };
  const fields = {
    message_index: feltObject(publicFields.message_index),
    ecdh_kind: feltObject(publicFields.ecdh_kind),
    coord_priv_key_hash: feltObject(publicFields.coord_priv_key_hash),
    base_hash: feltObject(publicFields.base_hash),
    shared_key_hash: feltObject(publicFields.shared_key_hash),
  };
  const publicOutput = nativeProcessDeactivatePublicOutput(
    PROCESS_DEACTIVATE_ECDH_NATIVE_CIRCUIT_ID,
    publicFields,
    result.params,
    ['message_index', 'ecdh_kind', 'coord_priv_key_hash', 'base_hash', 'shared_key_hash'],
  );

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: legacy.program_input.witness,
    },
    full_witness: legacy.full_witness,
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessDeactivateSignatureInput(rawInput, messageIndex, evaluated) {
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const legacy = buildCairoProcessDeactivateSignatureInput(rawInput, messageIndex, result);
  const transition = result.state.transitions[messageIndex];
  const input = transition.input;
  const publicFields = {
    message_index: BigInt(messageIndex),
    pub_key_hash: nativeHashPoint(input.stateLeaf.slice(0, 2), 'pubKey'),
    r8_hash: nativeHashPoint(input.cmdSigR8, 'r8'),
    packed_cmd_hash: nativePackedCmdHash(input.packedCmd),
    cmd_sig_s_hash: nativeHashU256(input.cmdSigS, 'cmdSigS'),
    signature_valid: transition.derived.signatureValid,
  };
  const fields = {
    message_index: feltObject(publicFields.message_index),
    pub_key_hash: feltObject(publicFields.pub_key_hash),
    r8_hash: feltObject(publicFields.r8_hash),
    packed_cmd_hash: feltObject(publicFields.packed_cmd_hash),
    cmd_sig_s_hash: feltObject(publicFields.cmd_sig_s_hash),
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
      'signature_valid',
    ],
  );

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: legacy.program_input.witness,
    },
    full_witness: legacy.full_witness,
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
  const legacy = buildCairoProcessDeactivateDecryptInput(rawInput, messageIndex, decryptKind, result);
  const transition = result.state.transitions[messageIndex];
  const current = decryptKind === 'current';
  const c1 = current ? transition.input.stateLeaf.slice(5, 7) : transition.input.c1;
  const c2 = current ? transition.input.stateLeaf.slice(7, 9) : transition.input.c2;
  const decrypt = current ? transition.derived.currentStateDecrypt : transition.derived.newStateDecrypt;
  const publicFields = {
    message_index: BigInt(messageIndex),
    decrypt_kind: current ? 0n : 1n,
    coord_priv_key_hash: nativeCoordPrivKeyHash(result.state.input.coordPrivKey),
    c1_hash: nativeHashPoint(c1, 'c1'),
    c2_hash: nativeHashPoint(c2, 'c2'),
    decrypt_is_odd: decrypt.isOdd,
  };
  const fields = {
    message_index: feltObject(publicFields.message_index),
    decrypt_kind: feltObject(publicFields.decrypt_kind),
    coord_priv_key_hash: feltObject(publicFields.coord_priv_key_hash),
    c1_hash: feltObject(publicFields.c1_hash),
    c2_hash: feltObject(publicFields.c2_hash),
    decrypt_is_odd: feltObject(publicFields.decrypt_is_odd),
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
    ],
  );

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: legacy.program_input.witness,
    },
    full_witness: legacy.full_witness,
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildCairoProcessDeactivateStepCoreInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  if (isEmptyDeactivateMessage(rawInput, messageIndex)) {
    throw new Error('cannot build deactivate core proof for an empty message slot');
  }
  const result = evaluated ?? evaluateProcessDeactivateMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const input = transition.input;
  const links = deactivateStepLinkFields(rawInput, messageIndex, result);
  const currentDeactivateCommitment = hashLeftRight(
    input.currentActiveStateRoot,
    input.currentDeactivateRoot,
  );
  const newDeactivateCommitment = hashLeftRight(
    transition.derived.newActiveStateRoot,
    transition.derived.newDeactivateRoot,
  );
  const publicFields = {
    messageIndex: BigInt(messageIndex),
    deactivateIndex: input.deactivateIndex,
    coordPubKeyHash: result.publicFields.coordPubKeyHash,
    coordPrivKeyHash: links.coordPrivKeyHash,
    previousMessageHash: result.boundary.derived.messageHashChain[messageIndex],
    nextMessageHash: result.boundary.derived.messageHashChain[messageIndex + 1],
    currentActiveStateRoot: input.currentActiveStateRoot,
    currentDeactivateRoot: input.currentDeactivateRoot,
    newActiveStateRoot: transition.derived.newActiveStateRoot,
    newDeactivateRoot: transition.derived.newDeactivateRoot,
    currentDeactivateCommitment,
    newDeactivateCommitment,
    currentStateRoot: result.publicFields.currentStateRoot,
    expectedPollId: result.publicFields.expectedPollId,
    ...links,
  };
  const fields = {
    message_index: publicFields.messageIndex,
    deactivate_index: splitObject(publicFields.deactivateIndex, 'deactivateIndex'),
    coord_pub_key_hash: splitObject(publicFields.coordPubKeyHash, 'coordPubKeyHash'),
    coord_priv_key_hash: splitObject(publicFields.coordPrivKeyHash, 'coordPrivKeyHash'),
    previous_message_hash: splitObject(publicFields.previousMessageHash, 'previousMessageHash'),
    next_message_hash: splitObject(publicFields.nextMessageHash, 'nextMessageHash'),
    current_active_state_root: splitObject(publicFields.currentActiveStateRoot, 'currentActiveStateRoot'),
    current_deactivate_root: splitObject(publicFields.currentDeactivateRoot, 'currentDeactivateRoot'),
    new_active_state_root: splitObject(publicFields.newActiveStateRoot, 'newActiveStateRoot'),
    new_deactivate_root: splitObject(publicFields.newDeactivateRoot, 'newDeactivateRoot'),
    current_deactivate_commitment: splitObject(publicFields.currentDeactivateCommitment, 'currentDeactivateCommitment'),
    new_deactivate_commitment: splitObject(publicFields.newDeactivateCommitment, 'newDeactivateCommitment'),
    current_state_root: splitObject(publicFields.currentStateRoot, 'currentStateRoot'),
    expected_poll_id: splitObject(publicFields.expectedPollId, 'expectedPollId'),
    enc_pub_key_hash: splitObject(publicFields.encPubKeyHash, 'encPubKeyHash'),
    command_shared_key_hash: splitObject(publicFields.commandSharedKeyHash, 'commandSharedKeyHash'),
    signature_pub_key_hash: splitObject(publicFields.signaturePubKeyHash, 'signaturePubKeyHash'),
    signature_r8_hash: splitObject(publicFields.signatureR8Hash, 'signatureR8Hash'),
    packed_cmd_hash: splitObject(publicFields.packedCmdHash, 'packedCmdHash'),
    cmd_sig_s: splitObject(publicFields.cmdSigS, 'cmdSigS'),
    signature_valid: splitObject(publicFields.signatureValid, 'signatureValid'),
    current_state_ciphertext_c1_hash: splitObject(publicFields.currentStateCiphertextC1Hash, 'currentStateCiphertextC1Hash'),
    current_state_ciphertext_c2_hash: splitObject(publicFields.currentStateCiphertextC2Hash, 'currentStateCiphertextC2Hash'),
    current_decrypt_is_odd: splitObject(publicFields.currentDecryptIsOdd, 'currentDecryptIsOdd'),
    new_state_ciphertext_c1_hash: splitObject(publicFields.newStateCiphertextC1Hash, 'newStateCiphertextC1Hash'),
    new_state_ciphertext_c2_hash: splitObject(publicFields.newStateCiphertextC2Hash, 'newStateCiphertextC2Hash'),
    new_decrypt_is_odd: splitObject(publicFields.newDecryptIsOdd, 'newDecryptIsOdd'),
    deactivate_pub_key_hash: splitObject(publicFields.deactivatePubKeyHash, 'deactivatePubKeyHash'),
    deactivate_shared_key_hash: splitObject(publicFields.deactivateSharedKeyHash, 'deactivateSharedKeyHash'),
  };
  const command = result.derived.messageCommands[messageIndex];
  const publicOutput = canonicalProcessDeactivateStepCorePublicOutput(publicFields, result.params);
  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        is_empty_msg: splitObject(input.isEmptyMsg, 'isEmptyMsg'),
        coord_priv_key: splitObject(result.state.input.coordPrivKey, 'coordPrivKey'),
        msg: splitVector10(rawInput.msgs[messageIndex], 'msg'),
        enc_pub_key: splitVector2(rawInput.encPubKeys[messageIndex], 'encPubKey'),
        command_shared_key: splitVector2(command.sharedKey, 'commandSharedKey'),
        decrypted_command: splitVector7(command.decryptedCommand, 'decryptedCommand'),
        c1: splitVector2(input.c1, 'c1'),
        c2: splitVector2(input.c2, 'c2'),
        state_leaf: splitVector10(input.stateLeaf, 'stateLeaf'),
        state_leaf_path_0: splitVector4(input.stateLeafPathElements[0], 'stateLeafPathElements[0]'),
        state_leaf_path_1: splitVector4(input.stateLeafPathElements[1], 'stateLeafPathElements[1]'),
        active_state_leaf_path_0: splitVector4(input.activeStateLeafPathElements[0], 'activeStateLeafPathElements[0]'),
        active_state_leaf_path_1: splitVector4(input.activeStateLeafPathElements[1], 'activeStateLeafPathElements[1]'),
        current_active_state: splitObject(input.currentActiveState, 'currentActiveState'),
        new_active_state: splitObject(input.newActiveState, 'newActiveState'),
        cmd_state_index: splitObject(input.cmdStateIndex, 'cmdStateIndex'),
        cmd_poll_id: splitObject(input.cmdPollId, 'cmdPollId'),
        cmd_sig_r8: splitVector2(input.cmdSigR8, 'cmdSigR8'),
        cmd_sig_s: splitObject(input.cmdSigS, 'cmdSigS'),
        packed_cmd: splitVector3(input.packedCmd, 'packedCmd'),
        deactivate_leaf_path_0: splitVector4(input.deactivateLeafPathElements[0], 'deactivateLeafPathElements[0]'),
        deactivate_leaf_path_1: splitVector4(input.deactivateLeafPathElements[1], 'deactivateLeafPathElements[1]'),
        deactivate_leaf_path_2: splitVector4(input.deactivateLeafPathElements[2], 'deactivateLeafPathElements[2]'),
        deactivate_leaf_path_3: splitVector4(input.deactivateLeafPathElements[3], 'deactivateLeafPathElements[3]'),
        current_decrypt_is_odd: splitObject(links.currentDecryptIsOdd, 'currentDecryptIsOdd'),
        new_decrypt_is_odd: splitObject(links.newDecryptIsOdd, 'newDecryptIsOdd'),
        signature_valid: splitObject(links.signatureValid, 'signatureValid'),
        deactivate_shared_key_hash: splitObject(links.deactivateSharedKeyHash, 'deactivateSharedKeyHash'),
        coord_priv_key_hash: hash2Claim(
          result.state.input.coordPrivKey,
          PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
          publicFields.coordPrivKeyHash,
          'coordPrivKeyHash',
        ),
        message_hash: hash13Claim(
          deactivateMessagePreimage(rawInput.msgs[messageIndex], rawInput.encPubKeys[messageIndex], publicFields.previousMessageHash),
          processDeactivateMessageHash(rawInput.msgs[messageIndex], rawInput.encPubKeys[messageIndex], publicFields.previousMessageHash),
          `deactivateMessageHash${messageIndex}`,
        ),
        current_deactivate_commitment: hash2Claim(
          publicFields.currentActiveStateRoot,
          publicFields.currentDeactivateRoot,
          publicFields.currentDeactivateCommitment,
          'currentDeactivateCommitment',
        ),
        new_deactivate_commitment: hash2Claim(
          publicFields.newActiveStateRoot,
          publicFields.newDeactivateRoot,
          publicFields.newDeactivateCommitment,
          'newDeactivateCommitment',
        ),
        enc_pub_key_hash: hash2Claim(rawInput.encPubKeys[messageIndex][0], rawInput.encPubKeys[messageIndex][1], links.encPubKeyHash, 'encPubKeyHash'),
        command_shared_key_hash: hash2Claim(command.sharedKey[0], command.sharedKey[1], links.commandSharedKeyHash, 'commandSharedKeyHash'),
        signature_pub_key_hash: hash2Claim(input.stateLeaf[0], input.stateLeaf[1], links.signaturePubKeyHash, 'signaturePubKeyHash'),
        signature_r8_hash: hash2Claim(input.cmdSigR8[0], input.cmdSigR8[1], links.signatureR8Hash, 'signatureR8Hash'),
        packed_cmd_hash: hash5Claim([input.packedCmd[0], input.packedCmd[1], input.packedCmd[2], 0n, 0n], links.packedCmdHash, 'packedCmdHash'),
        current_state_ciphertext_c1_hash: hash2Claim(input.stateLeaf[5], input.stateLeaf[6], links.currentStateCiphertextC1Hash, 'currentStateCiphertextC1Hash'),
        current_state_ciphertext_c2_hash: hash2Claim(input.stateLeaf[7], input.stateLeaf[8], links.currentStateCiphertextC2Hash, 'currentStateCiphertextC2Hash'),
        new_state_ciphertext_c1_hash: hash2Claim(input.c1[0], input.c1[1], links.newStateCiphertextC1Hash, 'newStateCiphertextC1Hash'),
        new_state_ciphertext_c2_hash: hash2Claim(input.c2[0], input.c2[1], links.newStateCiphertextC2Hash, 'newStateCiphertextC2Hash'),
        deactivate_pub_key_hash: hash2Claim(input.stateLeaf[0], input.stateLeaf[1], links.deactivatePubKeyHash, 'deactivatePubKeyHash'),
        state_leaf_hash: hash10Claim(input.stateLeaf, transition.derived.stateLeafHash, 'stateLeafHash'),
        deactivate_leaf: hash5Claim([...input.c1, ...input.c2, links.deactivateSharedKeyHash], transition.derived.deactivateLeaf, 'deactivateLeaf'),
      },
    },
    full_witness: {
      processDeactivate: rawInput,
      messageIndex,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
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

function pushVector5(args, value) {
  pushU256(args, value.v0);
  pushU256(args, value.v1);
  pushU256(args, value.v2);
  pushU256(args, value.v3);
  pushU256(args, value.v4);
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

function pushHash2Claim(args, value) {
  pushU256(args, value.in0);
  pushU256(args, value.in1);
  pushU256(args, value.out);
}

function pushHash5Claim(args, value) {
  pushVector5(args, value.inputs);
  pushU256(args, value.out);
}

function pushHash10Claim(args, value) {
  pushHash5Claim(args, value.first);
  pushHash5Claim(args, value.second);
  pushHash2Claim(args, value.out);
}

function pushHash13Claim(args, value) {
  pushHash5Claim(args, value.first);
  pushHash5Claim(args, value.second);
  pushHash5Claim(args, value.out);
}

function pushVector8(args, value) {
  pushU256(args, value.v0);
  pushU256(args, value.v1);
  pushU256(args, value.v2);
  pushU256(args, value.v3);
  pushU256(args, value.v4);
  pushU256(args, value.v5);
  pushU256(args, value.v6);
  pushU256(args, value.v7);
}

function pushSha256U256x8Claim(args, value) {
  pushVector8(args, value.inputs);
  pushU256(args, value.out);
}

function pushBabyjubScalarMulStep(args, step) {
  pushU256(args, step.bit);
  pushVector2(args, step.sum);
  pushVector2(args, step.next_acc);
  pushVector2(args, step.next_exp);
}

function pushBabyjubScalarMulWitness(args, witness) {
  pushU256(args, witness.scalar);
  pushVector2(args, witness.base);
  pushVector2(args, witness.expected);
  args.push(BigInt(witness.steps.length));
  for (const step of witness.steps) {
    pushBabyjubScalarMulStep(args, step);
  }
}

function pushBabyjubPoseidonSignatureWitness(args, witness) {
  pushVector2(args, witness.pub_key_x2);
  pushVector2(args, witness.pub_key_x4);
  pushVector2(args, witness.pub_key_x8);
  pushBabyjubScalarMulWitness(args, witness.s_base8);
  pushBabyjubScalarMulWitness(args, witness.h_pub_key_x8);
  pushVector2(args, witness.right);
}

function pushElGamalDecryptWitness(args, witness) {
  pushBabyjubScalarMulWitness(args, witness.scalar_mul);
  pushVector2(args, witness.decrypted_point);
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

function pushProcessDeactivateMessageCommandWitness(args, witness) {
  pushBabyjubScalarMulWitness(args, witness.ecdh);
  pushVector7(args, witness.decrypted_command);
}

function pushProcessDeactivateOneWitness(args, witness) {
  pushU256(args, witness.is_empty_msg);
  pushU256(args, witness.coord_priv_key);
  pushU256(args, witness.current_state_root);
  pushVector2(args, witness.c1);
  pushVector2(args, witness.c2);
  pushU256(args, witness.current_active_state_root);
  pushU256(args, witness.current_deactivate_root);
  pushVector10(args, witness.state_leaf);
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
  pushU256(args, witness.expected_poll_id);
  pushU256(args, witness.deactivate_index);
  pushVector4(args, witness.deactivate_leaf_path_0);
  pushVector4(args, witness.deactivate_leaf_path_1);
  pushVector4(args, witness.deactivate_leaf_path_2);
  pushVector4(args, witness.deactivate_leaf_path_3);
  pushElGamalDecryptWitness(args, witness.current_state_decrypt);
  pushElGamalDecryptWitness(args, witness.new_state_decrypt);
  pushBabyjubScalarMulWitness(args, witness.deactivate_ecdh);
  pushBabyjubPoseidonSignatureWitness(args, witness.signature);
  pushHash10Claim(args, witness.hashes.state_leaf_hash);
  pushHash2Claim(args, witness.hashes.shared_key_hash);
  pushHash5Claim(args, witness.hashes.deactivate_leaf);
}

function pushProcessDeactivateMessagesFields(args, fields) {
  pushU256(args, fields.new_deactivate_root);
  pushU256(args, fields.coord_pub_key_hash);
  pushU256(args, fields.batch_start_hash);
  pushU256(args, fields.batch_end_hash);
  pushU256(args, fields.current_deactivate_commitment);
  pushU256(args, fields.new_deactivate_commitment);
  pushU256(args, fields.current_state_root);
  pushU256(args, fields.expected_poll_id);
  pushU256(args, fields.input_hash);
}

function pushProcessDeactivateStepFields(args, fields) {
  args.push(BigInt(fields.message_index));
  pushU256(args, fields.deactivate_index);
  pushU256(args, fields.coord_pub_key_hash);
  pushU256(args, fields.previous_message_hash);
  pushU256(args, fields.next_message_hash);
  pushU256(args, fields.current_active_state_root);
  pushU256(args, fields.current_deactivate_root);
  pushU256(args, fields.new_active_state_root);
  pushU256(args, fields.new_deactivate_root);
  pushU256(args, fields.current_deactivate_commitment);
  pushU256(args, fields.new_deactivate_commitment);
  pushU256(args, fields.current_state_root);
  pushU256(args, fields.expected_poll_id);
}

function pushProcessDeactivateCoordKeyFields(args, fields) {
  pushU256(args, fields.coord_pub_key_hash);
  pushU256(args, fields.coord_priv_key_hash);
}

function pushNativeProcessDeactivateCoordKeyFields(args, fields) {
  pushFelt(args, fields.coord_pub_key_hash);
  pushFelt(args, fields.coord_priv_key_hash);
}

function pushProcessDeactivateEcdhFields(args, fields) {
  args.push(BigInt(fields.message_index));
  args.push(BigInt(fields.ecdh_kind));
  pushU256(args, fields.coord_priv_key_hash);
  pushU256(args, fields.base_hash);
  pushU256(args, fields.shared_key_hash);
}

function pushNativeProcessDeactivateEcdhFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.ecdh_kind);
  pushFelt(args, fields.coord_priv_key_hash);
  pushFelt(args, fields.base_hash);
  pushFelt(args, fields.shared_key_hash);
}

function pushProcessDeactivateSignatureFields(args, fields) {
  args.push(BigInt(fields.message_index));
  pushU256(args, fields.pub_key_hash);
  pushU256(args, fields.r8_hash);
  pushU256(args, fields.packed_cmd_hash);
  pushU256(args, fields.cmd_sig_s);
  pushU256(args, fields.signature_valid);
}

function pushNativeProcessDeactivateSignatureFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.pub_key_hash);
  pushFelt(args, fields.r8_hash);
  pushFelt(args, fields.packed_cmd_hash);
  pushFelt(args, fields.cmd_sig_s_hash);
  pushFelt(args, fields.signature_valid);
}

function pushProcessDeactivateDecryptFields(args, fields) {
  args.push(BigInt(fields.message_index));
  args.push(BigInt(fields.decrypt_kind));
  pushU256(args, fields.coord_priv_key_hash);
  pushU256(args, fields.c1_hash);
  pushU256(args, fields.c2_hash);
  pushU256(args, fields.decrypt_is_odd);
}

function pushNativeProcessDeactivateDecryptFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.decrypt_kind);
  pushFelt(args, fields.coord_priv_key_hash);
  pushFelt(args, fields.c1_hash);
  pushFelt(args, fields.c2_hash);
  pushFelt(args, fields.decrypt_is_odd);
}

function pushProcessDeactivateStepCoreFields(args, fields) {
  args.push(BigInt(fields.message_index));
  pushU256(args, fields.deactivate_index);
  pushU256(args, fields.coord_pub_key_hash);
  pushU256(args, fields.coord_priv_key_hash);
  pushU256(args, fields.previous_message_hash);
  pushU256(args, fields.next_message_hash);
  pushU256(args, fields.current_active_state_root);
  pushU256(args, fields.current_deactivate_root);
  pushU256(args, fields.new_active_state_root);
  pushU256(args, fields.new_deactivate_root);
  pushU256(args, fields.current_deactivate_commitment);
  pushU256(args, fields.new_deactivate_commitment);
  pushU256(args, fields.current_state_root);
  pushU256(args, fields.expected_poll_id);
  pushU256(args, fields.enc_pub_key_hash);
  pushU256(args, fields.command_shared_key_hash);
  pushU256(args, fields.signature_pub_key_hash);
  pushU256(args, fields.signature_r8_hash);
  pushU256(args, fields.packed_cmd_hash);
  pushU256(args, fields.cmd_sig_s);
  pushU256(args, fields.signature_valid);
  pushU256(args, fields.current_state_ciphertext_c1_hash);
  pushU256(args, fields.current_state_ciphertext_c2_hash);
  pushU256(args, fields.current_decrypt_is_odd);
  pushU256(args, fields.new_state_ciphertext_c1_hash);
  pushU256(args, fields.new_state_ciphertext_c2_hash);
  pushU256(args, fields.new_decrypt_is_odd);
  pushU256(args, fields.deactivate_pub_key_hash);
  pushU256(args, fields.deactivate_shared_key_hash);
}

function pushProcessDeactivateMessagesBoundaryWitness(args, witness) {
  pushVector2(args, witness.coord_pub_key);
  pushU256(args, witness.current_active_state_root);
  pushU256(args, witness.current_deactivate_root);
  pushU256(args, witness.batch_start_hash);
  pushU256(args, witness.batch_end_hash);
  pushU256(args, witness.current_state_root);
  pushU256(args, witness.expected_poll_id);
  pushVector10(args, witness.msg_0);
  pushVector10(args, witness.msg_1);
  pushVector10(args, witness.msg_2);
  pushVector10(args, witness.msg_3);
  pushVector10(args, witness.msg_4);
  pushVector2(args, witness.enc_pub_key_0);
  pushVector2(args, witness.enc_pub_key_1);
  pushVector2(args, witness.enc_pub_key_2);
  pushVector2(args, witness.enc_pub_key_3);
  pushVector2(args, witness.enc_pub_key_4);
  pushHash2Claim(args, witness.hashes.coord_pub_key_hash);
  pushSha256U256x8Claim(args, witness.hashes.input_hash);
  pushHash2Claim(args, witness.hashes.current_deactivate_commitment);
  pushHash13Claim(args, witness.hashes.message_hash_0);
  pushHash13Claim(args, witness.hashes.message_hash_1);
  pushHash13Claim(args, witness.hashes.message_hash_2);
  pushHash13Claim(args, witness.hashes.message_hash_3);
  pushHash13Claim(args, witness.hashes.message_hash_4);
}

function pushProcessDeactivateMessagesStateTransitionWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushU256(args, witness.current_state_root);
  pushU256(args, witness.current_active_state_root);
  pushU256(args, witness.current_deactivate_root);
  pushU256(args, witness.expected_poll_id);
  pushU256(args, witness.deactivate_index_0);
  pushProcessDeactivateOneWitness(args, witness.process_one_0);
  pushProcessDeactivateOneWitness(args, witness.process_one_1);
  pushProcessDeactivateOneWitness(args, witness.process_one_2);
  pushProcessDeactivateOneWitness(args, witness.process_one_3);
  pushProcessDeactivateOneWitness(args, witness.process_one_4);
}

function pushProcessDeactivateMessagesStatefulWitness(args, witness) {
  pushProcessDeactivateMessagesBoundaryWitness(args, witness.boundary);
  pushProcessDeactivateMessagesStateTransitionWitness(args, witness.state_transition);
  pushBabyjubScalarMulWitness(args, witness.coord_pub_key);
  pushProcessDeactivateMessageCommandWitness(args, witness.command_0);
  pushProcessDeactivateMessageCommandWitness(args, witness.command_1);
  pushProcessDeactivateMessageCommandWitness(args, witness.command_2);
  pushProcessDeactivateMessageCommandWitness(args, witness.command_3);
  pushProcessDeactivateMessageCommandWitness(args, witness.command_4);
  pushHash2Claim(args, witness.new_deactivate_commitment);
}

function pushProcessDeactivateMessageStepWitness(args, witness) {
  pushVector2(args, witness.coord_pub_key);
  pushVector10(args, witness.msg);
  pushVector2(args, witness.enc_pub_key);
  pushU256(args, witness.coord_priv_key);
  pushBabyjubScalarMulWitness(args, witness.coord_pub_key_scalar_mul);
  pushHash2Claim(args, witness.coord_pub_key_hash);
  pushHash13Claim(args, witness.message_hash);
  pushProcessDeactivateMessageCommandWitness(args, witness.command);
  pushProcessDeactivateOneWitness(args, witness.process_one);
  pushHash2Claim(args, witness.current_deactivate_commitment);
  pushHash2Claim(args, witness.new_deactivate_commitment);
}

function pushProcessDeactivateCoordKeyWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.coord_pub_key);
  pushBabyjubScalarMulWitness(args, witness.coord_pub_key_scalar_mul);
  pushHash2Claim(args, witness.coord_pub_key_hash);
  pushHash2Claim(args, witness.coord_priv_key_hash);
}

function pushProcessDeactivateEcdhWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.base);
  pushBabyjubScalarMulWitness(args, witness.ecdh);
  pushHash2Claim(args, witness.coord_priv_key_hash);
  pushHash2Claim(args, witness.base_hash);
  pushHash2Claim(args, witness.shared_key_hash);
}

function pushProcessDeactivateSignatureWitness(args, witness) {
  pushVector2(args, witness.pub_key);
  pushVector2(args, witness.r8);
  pushU256(args, witness.s);
  pushVector3(args, witness.packed_cmd);
  pushBabyjubPoseidonSignatureWitness(args, witness.signature);
  pushHash2Claim(args, witness.pub_key_hash);
  pushHash2Claim(args, witness.r8_hash);
  pushHash5Claim(args, witness.packed_cmd_hash);
}

function pushProcessDeactivateDecryptWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.c1);
  pushVector2(args, witness.c2);
  pushElGamalDecryptWitness(args, witness.decrypt);
  pushHash2Claim(args, witness.coord_priv_key_hash);
  pushHash2Claim(args, witness.c1_hash);
  pushHash2Claim(args, witness.c2_hash);
}

function pushProcessDeactivateStepCoreWitness(args, witness) {
  pushU256(args, witness.is_empty_msg);
  pushU256(args, witness.coord_priv_key);
  pushVector10(args, witness.msg);
  pushVector2(args, witness.enc_pub_key);
  pushVector2(args, witness.command_shared_key);
  pushVector7(args, witness.decrypted_command);
  pushVector2(args, witness.c1);
  pushVector2(args, witness.c2);
  pushVector10(args, witness.state_leaf);
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
  pushU256(args, witness.deactivate_shared_key_hash);
  pushHash2Claim(args, witness.coord_priv_key_hash);
  pushHash13Claim(args, witness.message_hash);
  pushHash2Claim(args, witness.current_deactivate_commitment);
  pushHash2Claim(args, witness.new_deactivate_commitment);
  pushHash2Claim(args, witness.enc_pub_key_hash);
  pushHash2Claim(args, witness.command_shared_key_hash);
  pushHash2Claim(args, witness.signature_pub_key_hash);
  pushHash2Claim(args, witness.signature_r8_hash);
  pushHash5Claim(args, witness.packed_cmd_hash);
  pushHash2Claim(args, witness.current_state_ciphertext_c1_hash);
  pushHash2Claim(args, witness.current_state_ciphertext_c2_hash);
  pushHash2Claim(args, witness.new_state_ciphertext_c1_hash);
  pushHash2Claim(args, witness.new_state_ciphertext_c2_hash);
  pushHash2Claim(args, witness.deactivate_pub_key_hash);
  pushHash10Claim(args, witness.state_leaf_hash);
  pushHash5Claim(args, witness.deactivate_leaf);
}

export function serializeCairoProcessDeactivateOneExecutableArgs(cairoInput) {
  const args = [];
  pushProcessDeactivateOneWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessDeactivateMessagesBoundaryExecutableArgs(cairoInput) {
  const args = [];
  pushProcessDeactivateMessagesFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateMessagesBoundaryWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessDeactivateMessageStepExecutableArgs(cairoInput) {
  const args = [];
  pushProcessDeactivateStepFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateMessageStepWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessDeactivateCoordKeyExecutableArgs(cairoInput) {
  const args = [];
  pushProcessDeactivateCoordKeyFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateCoordKeyWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessDeactivateCoordKeyExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessDeactivateCoordKeyFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateCoordKeyWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessDeactivateEcdhExecutableArgs(cairoInput) {
  const args = [];
  pushProcessDeactivateEcdhFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateEcdhWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessDeactivateEcdhExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessDeactivateEcdhFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateEcdhWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessDeactivateSignatureExecutableArgs(cairoInput) {
  const args = [];
  pushProcessDeactivateSignatureFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateSignatureWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessDeactivateSignatureExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessDeactivateSignatureFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateSignatureWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessDeactivateDecryptExecutableArgs(cairoInput) {
  const args = [];
  pushProcessDeactivateDecryptFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateDecryptWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessDeactivateDecryptExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessDeactivateDecryptFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateDecryptWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessDeactivateStepCoreExecutableArgs(cairoInput) {
  const args = [];
  pushProcessDeactivateStepCoreFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateStepCoreWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessDeactivateMessagesStateTransitionExecutableArgs(cairoInput) {
  const args = [];
  pushProcessDeactivateMessagesStateTransitionWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessDeactivateMessagesStatefulExecutableArgs(cairoInput) {
  const args = [];
  pushProcessDeactivateMessagesFields(args, cairoInput.program_input.fields);
  pushProcessDeactivateMessagesStatefulWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}
