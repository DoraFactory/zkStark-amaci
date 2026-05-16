import { bigintToHex, decimalize, splitU256ToU128 } from '../compat/encoding.mjs';
import {
  NATIVE_PUBLIC_OUTPUT_VERSION,
  PROCESS_MESSAGE_COORD_KEY_NATIVE_CIRCUIT_ID,
  PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
  PROCESS_MESSAGE_ECDH_NATIVE_CIRCUIT_ID,
  PROCESS_MESSAGE_NATIVE_COORD_KEY_BINDING_DOMAIN,
  PROCESS_MESSAGE_NATIVE_COMMAND_AUTH_DOMAIN,
  PROCESS_MESSAGE_NATIVE_COMMAND_PLAINTEXT_DOMAIN,
  PROCESS_MESSAGE_NATIVE_SHARED_KEY_DOMAIN,
  PROCESS_MESSAGE_SIGNATURE_NATIVE_CIRCUIT_ID,
  PROCESS_MESSAGE_STEP_CORE_NATIVE_CIRCUIT_ID,
  PUBLIC_OUTPUT_MAGIC,
  STARKNET_POSEIDON_HASH_SCHEME,
} from '../constants.mjs';
import { poseidonManyFelts } from '../integrity/hashes.mjs';
import {
  buildCairoBabyjubScalarMulInput,
  buildCairoEcdhSharedKeyInput,
  buildCairoBabyjubPoseidonSignatureInput,
} from '../compat/babyjub-cairo-input.mjs';
import { BABYJUB_BASE8, buildElGamalDecryptWitness } from '../compat/babyjub.mjs';
import { hash5, hash13, hashLeftRight } from '../compat/poseidon.mjs';
import { toStarkFelt } from '../tally/native-tally-votes.mjs';
import {
  canonicalProcessMessageCoordKeyPublicOutput,
  canonicalProcessMessageEcdhPublicOutput,
  canonicalProcessMessageSignaturePublicOutput,
  canonicalProcessMessageStepCorePublicOutput,
  canonicalProcessMessageStepPublicOutput,
} from '../public-output.mjs';
import {
  evaluateProcessMessagesStateful,
  evaluateProcessMessagesStateTransitions,
  processMessageHash,
} from './process-messages.mjs';
import { nativeProcessMessageTransitionContexts } from './native-process-roots.mjs';
import { evaluateProcessOneStateTransition } from './process-one.mjs';

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

function splitVector8(values, label) {
  if (!Array.isArray(values) || values.length !== 8) {
    throw new Error(`${label} must contain eight values`);
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
    throw new Error(`${label}.out mismatch: expected ${expectedOut.toString()}, got ${out.toString()}`);
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
    throw new Error(`${label}.out mismatch: expected ${expectedOut.toString()}, got ${out.toString()}`);
  }
  return {
    first: hash5Claim(firstInputs, firstHash, `${label}.first`),
    second: hash5Claim(secondInputs, secondHash, `${label}.second`),
    out: hash5Claim(finalInputs, out, `${label}.out`),
  };
}

function sha256U256x8Claim(inputs, out, label) {
  return {
    inputs: splitVector8(inputs, `${label}.inputs`),
    out: splitObject(out, `${label}.out`),
  };
}

function messagePreimage(message, encPubKey, prevHash) {
  return [
    ...message.map(BigInt),
    BigInt(encPubKey[0]),
    BigInt(encPubKey[1]),
    BigInt(prevHash),
  ];
}

function buildMessageHashClaims(rawInput) {
  const claims = [];
  let prevHash = BigInt(rawInput.batchStartHash);
  for (let i = 0; i < 5; i += 1) {
    const preimage = messagePreimage(rawInput.msgs[i], rawInput.encPubKeys[i], prevHash);
    const messageHash = processMessageHash(rawInput.msgs[i], rawInput.encPubKeys[i], prevHash);
    claims.push(hash13Claim(preimage, messageHash, `messageHash${i}`));
    prevHash = BigInt(rawInput.encPubKeys[i][0]) === 0n ? prevHash : messageHash;
  }
  return claims;
}

function buildCairoProcessMessagesBoundaryWitness(rawInput, evaluated) {
  const messageHashClaims = buildMessageHashClaims(rawInput);
  const { isQuadraticCost, numSignUps, maxVoteOptions } = evaluated.derived;
  return {
    is_quadratic_cost: splitObject(isQuadraticCost, 'isQuadraticCost'),
    num_signups: splitObject(numSignUps, 'numSignUps'),
    max_vote_options: splitObject(maxVoteOptions, 'maxVoteOptions'),
    coord_pub_key: splitVector2(rawInput.coordPubKey, 'coordPubKey'),
    current_state_root: splitObject(rawInput.currentStateRoot, 'currentStateRoot'),
    current_state_salt: splitObject(rawInput.currentStateSalt, 'currentStateSalt'),
    new_state_root: splitObject(rawInput.newStateRoot, 'newStateRoot'),
    new_state_salt: splitObject(rawInput.newStateSalt, 'newStateSalt'),
    active_state_root: splitObject(rawInput.activeStateRoot, 'activeStateRoot'),
    deactivate_root: splitObject(rawInput.deactivateRoot, 'deactivateRoot'),
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
          evaluated.publicFields.packedVals,
          evaluated.publicFields.coordPubKeyHash,
          evaluated.publicFields.batchStartHash,
          evaluated.publicFields.batchEndHash,
          evaluated.publicFields.currentStateCommitment,
          evaluated.publicFields.newStateCommitment,
          evaluated.publicFields.deactivateCommitment,
          evaluated.publicFields.expectedPollId,
        ],
        evaluated.publicFields.inputHash,
        'inputHash',
      ),
      current_state_commitment: hash2Claim(
        rawInput.currentStateRoot,
        rawInput.currentStateSalt,
        evaluated.publicFields.currentStateCommitment,
        'currentStateCommitment',
      ),
      new_state_commitment: hash2Claim(
        rawInput.newStateRoot,
        rawInput.newStateSalt,
        evaluated.publicFields.newStateCommitment,
        'newStateCommitment',
      ),
      deactivate_commitment: hash2Claim(
        rawInput.activeStateRoot,
        rawInput.deactivateRoot,
        evaluated.publicFields.deactivateCommitment,
        'deactivateCommitment',
      ),
      message_hash_0: messageHashClaims[0],
      message_hash_1: messageHashClaims[1],
      message_hash_2: messageHashClaims[2],
      message_hash_3: messageHashClaims[3],
      message_hash_4: messageHashClaims[4],
    },
  };
}

export function buildCairoProcessMessagesInput(rawInput, evaluated) {
  const fields = {
    packed_vals: splitObject(evaluated.publicFields.packedVals, 'packedVals'),
    coord_pub_key_hash: splitObject(evaluated.publicFields.coordPubKeyHash, 'coordPubKeyHash'),
    batch_start_hash: splitObject(evaluated.publicFields.batchStartHash, 'batchStartHash'),
    batch_end_hash: splitObject(evaluated.publicFields.batchEndHash, 'batchEndHash'),
    current_state_commitment: splitObject(
      evaluated.publicFields.currentStateCommitment,
      'currentStateCommitment',
    ),
    new_state_commitment: splitObject(evaluated.publicFields.newStateCommitment, 'newStateCommitment'),
    deactivate_commitment: splitObject(evaluated.publicFields.deactivateCommitment, 'deactivateCommitment'),
    expected_poll_id: splitObject(evaluated.publicFields.expectedPollId, 'expectedPollId'),
    input_hash: splitObject(evaluated.publicFields.inputHash, 'inputHash'),
  };

  return {
    fields,
    witness_summary: {
      current_state_root: splitObject(rawInput.currentStateRoot, 'currentStateRoot'),
      new_state_root: splitObject(rawInput.newStateRoot, 'newStateRoot'),
      active_state_root: splitObject(rawInput.activeStateRoot, 'activeStateRoot'),
    },
    program_input: {
      fields,
      witness: buildCairoProcessMessagesBoundaryWitness(rawInput, evaluated),
    },
    full_witness: rawInput,
    public_output: evaluated.publicOutput.decimalFelts,
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

function buildProcessOneStateDecryptWitness(result, messageIndex = 0) {
  const { input } = result;
  const stateDecrypt = buildElGamalDecryptWitness({
    privKey: input.coordPrivKey,
    c1: [input.stateLeaf[5], input.stateLeaf[6]],
    c2: [input.stateLeaf[7], input.stateLeaf[8]],
  });
  if (1n - stateDecrypt.isOdd !== input.isDecryptionActive) {
    throw new Error(
      `ElGamal decrypt result does not match ProcessOne ${messageIndex} isDecryptionActive`,
    );
  }
  return {
    scalar_mul: buildCairoBabyjubScalarMulInput(stateDecrypt.scalarMul).program_input.witness,
    decrypted_point: splitVector2(
      stateDecrypt.decryptedPoint,
      `stateDecrypt[${messageIndex}].decryptedPoint`,
    ),
  };
}

export function buildCairoProcessOneStateTransitionInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessOneStateTransition(rawInput);
  const { derived } = result;
  const witness = buildProcessOneStateTransitionWitnessFromEvaluation(result);

  return {
    program_input: {
      witness,
    },
    expected_output: {
      new_state_root: splitObject(derived.newStateRoot, 'newStateRoot'),
    },
    full_witness: rawInput,
  };
}

export function buildCairoProcessOneWithEcdhInput(rawInput, ecdhInput, evaluated) {
  const result = evaluated ?? evaluateProcessOneStateTransition(rawInput);
  const ecdhCairoInput = buildCairoEcdhSharedKeyInput(ecdhInput);
  const [expectedX, expectedY] = ecdhCairoInput.expected;
  if (expectedX !== result.input.sharedKey[0] || expectedY !== result.input.sharedKey[1]) {
    throw new Error('ECDH shared key does not match ProcessOne sharedKey witness');
  }

  return {
    program_input: {
      witness: {
        ecdh: ecdhCairoInput.program_input.witness,
        process_one: buildProcessOneStateTransitionWitnessFromEvaluation(result),
      },
    },
    expected_output: {
      new_state_root: splitObject(result.derived.newStateRoot, 'newStateRoot'),
    },
    full_witness: {
      processOne: rawInput,
      ecdh: ecdhCairoInput.full_witness,
    },
  };
}

function buildProcessOneSignatureInput(result) {
  const input = result.input;
  const signatureCairoInput = buildCairoBabyjubPoseidonSignatureInput({
    pubKey: [input.stateLeaf[0], input.stateLeaf[1]],
    r8: input.cmdSigR8,
    s: input.cmdSigS,
    preimage: input.packedCommand,
  });
  if (signatureCairoInput.valid !== input.isSignatureValid) {
    throw new Error('signature verification result does not match ProcessOne isSignatureValid');
  }
  return signatureCairoInput;
}

export function buildCairoProcessOneWithSignatureInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessOneStateTransition(rawInput);
  const signatureCairoInput = buildProcessOneSignatureInput(result);

  return {
    program_input: {
      witness: {
        signature: signatureCairoInput.program_input.witness,
        process_one: buildProcessOneStateTransitionWitnessFromEvaluation(result),
      },
    },
    expected_output: {
      new_state_root: splitObject(result.derived.newStateRoot, 'newStateRoot'),
    },
    full_witness: {
      processOne: rawInput,
      signature: signatureCairoInput.full_witness,
    },
  };
}

export function buildCairoProcessOneWithEcdhSignatureInput(rawInput, ecdhInput, evaluated) {
  const result = evaluated ?? evaluateProcessOneStateTransition(rawInput);
  const ecdhCairoInput = buildCairoEcdhSharedKeyInput(ecdhInput);
  const [expectedX, expectedY] = ecdhCairoInput.expected;
  if (expectedX !== result.input.sharedKey[0] || expectedY !== result.input.sharedKey[1]) {
    throw new Error('ECDH shared key does not match ProcessOne sharedKey witness');
  }
  const signatureCairoInput = buildProcessOneSignatureInput(result);

  return {
    program_input: {
      witness: {
        ecdh: ecdhCairoInput.program_input.witness,
        signature: signatureCairoInput.program_input.witness,
        process_one: buildProcessOneStateTransitionWitnessFromEvaluation(result),
      },
    },
    expected_output: {
      new_state_root: splitObject(result.derived.newStateRoot, 'newStateRoot'),
    },
    full_witness: {
      processOne: rawInput,
      ecdh: ecdhCairoInput.full_witness,
      signature: signatureCairoInput.full_witness,
    },
  };
}

function assertMessageIndex(messageIndex) {
  if (!Number.isInteger(messageIndex) || messageIndex < 0 || messageIndex >= 5) {
    throw new Error('messageIndex must be an integer in [0, 4]');
  }
}

function coordPrivKeyHash(coordPrivKey) {
  return hashLeftRight(BigInt(coordPrivKey), PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN);
}

function packedCommandHash(packedCommand) {
  return hash5([packedCommand[0], packedCommand[1], packedCommand[2], 0n, 0n]);
}

function buildCoordPubKeyScalarMulInput(rawInput) {
  if (rawInput.coordPrivKey === undefined) {
    throw new Error('coordPrivKey is required to build coordinator public-key witness input');
  }
  const coordPubKeyCairoInput = buildCairoBabyjubScalarMulInput({
    scalar: rawInput.coordPrivKey,
    base: BABYJUB_BASE8.map((value) => value.toString()),
  });
  const [coordPubKeyX, coordPubKeyY] = coordPubKeyCairoInput.expected;
  if (
    coordPubKeyX !== BigInt(rawInput.coordPubKey[0]) ||
    coordPubKeyY !== BigInt(rawInput.coordPubKey[1])
  ) {
    throw new Error('coordPrivKey does not match coordPubKey');
  }
  return coordPubKeyCairoInput;
}

export function buildCairoProcessMessageStepWithEcdhSignatureInput(
  rawInput,
  messageIndex,
  evaluated,
) {
  assertMessageIndex(messageIndex);
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const publicFields = {
    messageIndex: BigInt(messageIndex),
    packedVals: result.publicFields.packedVals,
    coordPubKeyHash: result.publicFields.coordPubKeyHash,
    previousMessageHash: result.derived.messageHashChain[messageIndex],
    nextMessageHash: result.derived.messageHashChain[messageIndex + 1],
    currentStateRoot: transition.input.currentStateRoot,
    newStateRoot: transition.derived.newStateRoot,
    currentStateCommitment: result.publicFields.currentStateCommitment,
    newStateCommitment: result.publicFields.newStateCommitment,
    activeStateRoot: result.state.derived.activeStateRoot,
    expectedPollId: result.publicFields.expectedPollId,
  };
  const fields = {
    message_index: publicFields.messageIndex,
    packed_vals: splitObject(publicFields.packedVals, 'packedVals'),
    coord_pub_key_hash: splitObject(publicFields.coordPubKeyHash, 'coordPubKeyHash'),
    previous_message_hash: splitObject(
      publicFields.previousMessageHash,
      'previousMessageHash',
    ),
    next_message_hash: splitObject(publicFields.nextMessageHash, 'nextMessageHash'),
    current_state_root: splitObject(publicFields.currentStateRoot, 'currentStateRoot'),
    new_state_root: splitObject(publicFields.newStateRoot, 'newStateRoot'),
    current_state_commitment: splitObject(
      publicFields.currentStateCommitment,
      'currentStateCommitment',
    ),
    new_state_commitment: splitObject(publicFields.newStateCommitment, 'newStateCommitment'),
    active_state_root: splitObject(publicFields.activeStateRoot, 'activeStateRoot'),
    expected_poll_id: splitObject(publicFields.expectedPollId, 'expectedPollId'),
  };
  const coordPubKeyCairoInput = buildCoordPubKeyScalarMulInput(rawInput);
  const ecdhCairoInput = buildCairoEcdhSharedKeyInput(ecdhInputForMessage(rawInput, messageIndex));
  if (BigInt(rawInput.encPubKeys[messageIndex][0]) !== 0n) {
    const [expectedX, expectedY] = ecdhCairoInput.expected;
    if (expectedX !== transition.input.sharedKey[0] || expectedY !== transition.input.sharedKey[1]) {
      throw new Error(`ECDH shared key does not match ProcessOne ${messageIndex} sharedKey witness`);
    }
  }
  const signatureCairoInput = buildProcessOneSignatureInputForTransition(transition, messageIndex);
  const publicOutput = canonicalProcessMessageStepPublicOutput(publicFields, result.params);

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        is_quadratic_cost: splitObject(result.derived.isQuadraticCost, 'isQuadraticCost'),
        num_signups: splitObject(result.derived.numSignUps, 'numSignUps'),
        max_vote_options: splitObject(result.derived.maxVoteOptions, 'maxVoteOptions'),
        coord_pub_key: splitVector2(rawInput.coordPubKey, 'coordPubKey'),
        enc_pub_key: splitVector2(rawInput.encPubKeys[messageIndex], 'encPubKey'),
        msg: splitVector10(rawInput.msgs[messageIndex], 'msg'),
        coord_priv_key: splitObject(rawInput.coordPrivKey, 'coordPrivKey'),
        current_state_salt: splitObject(rawInput.currentStateSalt, 'currentStateSalt'),
        new_state_salt: splitObject(rawInput.newStateSalt, 'newStateSalt'),
        coord_pub_key_scalar_mul: coordPubKeyCairoInput.program_input.witness,
        coord_pub_key_hash: hash2Claim(
          rawInput.coordPubKey[0],
          rawInput.coordPubKey[1],
          publicFields.coordPubKeyHash,
          'coordPubKeyHash',
        ),
        current_state_commitment: hash2Claim(
          rawInput.currentStateRoot,
          rawInput.currentStateSalt,
          publicFields.currentStateCommitment,
          'currentStateCommitment',
        ),
        new_state_commitment: hash2Claim(
          rawInput.newStateRoot,
          rawInput.newStateSalt,
          publicFields.newStateCommitment,
          'newStateCommitment',
        ),
        message_hash: hash13Claim(
          messagePreimage(
            rawInput.msgs[messageIndex],
            rawInput.encPubKeys[messageIndex],
            publicFields.previousMessageHash,
          ),
          processMessageHash(
            rawInput.msgs[messageIndex],
            rawInput.encPubKeys[messageIndex],
            publicFields.previousMessageHash,
          ),
          `messageHash${messageIndex}`,
        ),
        state_decrypt: buildProcessOneStateDecryptWitness(transition, messageIndex),
        ecdh: ecdhCairoInput.program_input.witness,
        signature: signatureCairoInput.program_input.witness,
        process_one: buildProcessOneStateTransitionWitnessFromEvaluation(transition),
      },
    },
    full_witness: {
      processMessages: rawInput,
      messageIndex,
      ecdh: ecdhCairoInput.full_witness,
      signature: signatureCairoInput.full_witness,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildCairoProcessMessageCoordKeyInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const coordPubKeyCairoInput = buildCoordPubKeyScalarMulInput(rawInput);
  const publicFields = {
    coordPubKeyHash: result.publicFields.coordPubKeyHash,
    coordPrivKeyHash: coordPrivKeyHash(rawInput.coordPrivKey),
  };
  const fields = {
    coord_pub_key_hash: splitObject(publicFields.coordPubKeyHash, 'coordPubKeyHash'),
    coord_priv_key_hash: splitObject(publicFields.coordPrivKeyHash, 'coordPrivKeyHash'),
  };
  const publicOutput = canonicalProcessMessageCoordKeyPublicOutput(publicFields, result.params);

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        coord_priv_key: splitObject(rawInput.coordPrivKey, 'coordPrivKey'),
        coord_pub_key: splitVector2(rawInput.coordPubKey, 'coordPubKey'),
        coord_pub_key_scalar_mul: coordPubKeyCairoInput.program_input.witness,
        coord_pub_key_hash: hash2Claim(
          rawInput.coordPubKey[0],
          rawInput.coordPubKey[1],
          publicFields.coordPubKeyHash,
          'coordPubKeyHash',
        ),
        coord_priv_key_hash: hash2Claim(
          rawInput.coordPrivKey,
          PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
          publicFields.coordPrivKeyHash,
          'coordPrivKeyHash',
        ),
      },
    },
    full_witness: {
      processMessages: rawInput,
      coordPubKey: coordPubKeyCairoInput.full_witness,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

function isEmptyMessage(rawInput, messageIndex) {
  return BigInt(rawInput.encPubKeys[messageIndex][0]) === 0n;
}

function processMessageStepLinkFields(rawInput, messageIndex, result) {
  const transition = result.state.transitions[messageIndex];
  const sharedKey = transition.input.sharedKey;
  const stateLeafPubKey = [transition.input.stateLeaf[0], transition.input.stateLeaf[1]];
  const signatureR8 = transition.input.cmdSigR8;
  const commandHash = packedCommandHash(transition.input.packedCommand);
  return {
    coordPrivKeyHash: coordPrivKeyHash(rawInput.coordPrivKey),
    encPubKeyHash: hashLeftRight(rawInput.encPubKeys[messageIndex][0], rawInput.encPubKeys[messageIndex][1]),
    sharedKeyHash: hashLeftRight(sharedKey[0], sharedKey[1]),
    signaturePubKeyHash: hashLeftRight(stateLeafPubKey[0], stateLeafPubKey[1]),
    signatureR8Hash: hashLeftRight(signatureR8[0], signatureR8[1]),
    packedCommandHash: commandHash,
    cmdSigS: transition.input.cmdSigS,
    isSignatureValid: transition.input.isSignatureValid,
  };
}

export function buildCairoProcessMessageEcdhInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  if (isEmptyMessage(rawInput, messageIndex)) {
    throw new Error('cannot build ECDH proof for an empty message slot');
  }
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const linkFields = processMessageStepLinkFields(rawInput, messageIndex, result);
  const ecdhCairoInput = buildCairoEcdhSharedKeyInput(ecdhInputForMessage(rawInput, messageIndex));
  const [expectedX, expectedY] = ecdhCairoInput.expected;
  if (expectedX !== transition.input.sharedKey[0] || expectedY !== transition.input.sharedKey[1]) {
    throw new Error(`ECDH shared key does not match ProcessOne ${messageIndex} sharedKey witness`);
  }
  const publicFields = {
    messageIndex: BigInt(messageIndex),
    coordPrivKeyHash: linkFields.coordPrivKeyHash,
    encPubKeyHash: linkFields.encPubKeyHash,
    sharedKeyHash: linkFields.sharedKeyHash,
  };
  const fields = {
    message_index: publicFields.messageIndex,
    coord_priv_key_hash: splitObject(publicFields.coordPrivKeyHash, 'coordPrivKeyHash'),
    enc_pub_key_hash: splitObject(publicFields.encPubKeyHash, 'encPubKeyHash'),
    shared_key_hash: splitObject(publicFields.sharedKeyHash, 'sharedKeyHash'),
  };
  const publicOutput = canonicalProcessMessageEcdhPublicOutput(publicFields, result.params);

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        coord_priv_key: splitObject(rawInput.coordPrivKey, 'coordPrivKey'),
        enc_pub_key: splitVector2(rawInput.encPubKeys[messageIndex], 'encPubKey'),
        ecdh: ecdhCairoInput.program_input.witness,
        coord_priv_key_hash: hash2Claim(
          rawInput.coordPrivKey,
          PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
          publicFields.coordPrivKeyHash,
          'coordPrivKeyHash',
        ),
        enc_pub_key_hash: hash2Claim(
          rawInput.encPubKeys[messageIndex][0],
          rawInput.encPubKeys[messageIndex][1],
          publicFields.encPubKeyHash,
          'encPubKeyHash',
        ),
        shared_key_hash: hash2Claim(
          transition.input.sharedKey[0],
          transition.input.sharedKey[1],
          publicFields.sharedKeyHash,
          'sharedKeyHash',
        ),
      },
    },
    full_witness: {
      processMessages: rawInput,
      messageIndex,
      ecdh: ecdhCairoInput.full_witness,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildCairoProcessMessageSignatureInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  if (isEmptyMessage(rawInput, messageIndex)) {
    throw new Error('cannot build signature proof for an empty message slot');
  }
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const signatureCairoInput = buildProcessOneSignatureInputForTransition(transition, messageIndex);
  const linkFields = processMessageStepLinkFields(rawInput, messageIndex, result);
  const publicFields = {
    messageIndex: BigInt(messageIndex),
    pubKeyHash: linkFields.signaturePubKeyHash,
    r8Hash: linkFields.signatureR8Hash,
    packedCommandHash: linkFields.packedCommandHash,
    cmdSigS: linkFields.cmdSigS,
    isSignatureValid: linkFields.isSignatureValid,
  };
  const fields = {
    message_index: publicFields.messageIndex,
    pub_key_hash: splitObject(publicFields.pubKeyHash, 'pubKeyHash'),
    r8_hash: splitObject(publicFields.r8Hash, 'r8Hash'),
    packed_command_hash: splitObject(publicFields.packedCommandHash, 'packedCommandHash'),
    cmd_sig_s: splitObject(publicFields.cmdSigS, 'cmdSigS'),
    is_signature_valid: splitObject(publicFields.isSignatureValid, 'isSignatureValid'),
  };
  const packedHashInputs = [
    transition.input.packedCommand[0],
    transition.input.packedCommand[1],
    transition.input.packedCommand[2],
    0n,
    0n,
  ];
  const publicOutput = canonicalProcessMessageSignaturePublicOutput(publicFields, result.params);

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        pub_key: splitVector2([transition.input.stateLeaf[0], transition.input.stateLeaf[1]], 'pubKey'),
        r8: splitVector2(transition.input.cmdSigR8, 'r8'),
        s: splitObject(transition.input.cmdSigS, 's'),
        packed_command: splitVector3(transition.input.packedCommand, 'packedCommand'),
        signature: signatureCairoInput.program_input.witness,
        pub_key_hash: hash2Claim(
          transition.input.stateLeaf[0],
          transition.input.stateLeaf[1],
          publicFields.pubKeyHash,
          'pubKeyHash',
        ),
        r8_hash: hash2Claim(
          transition.input.cmdSigR8[0],
          transition.input.cmdSigR8[1],
          publicFields.r8Hash,
          'r8Hash',
        ),
        packed_command_hash: hash5Claim(
          packedHashInputs,
          publicFields.packedCommandHash,
          'packedCommandHash',
        ),
      },
    },
    full_witness: {
      processMessages: rawInput,
      messageIndex,
      signature: signatureCairoInput.full_witness,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
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

export function buildNativeCairoProcessMessageSignatureInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  if (isEmptyMessage(rawInput, messageIndex)) {
    throw new Error('cannot build native signature proof for an empty message slot');
  }
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

export function buildCairoProcessMessageStepCoreInput(rawInput, messageIndex, evaluated) {
  assertMessageIndex(messageIndex);
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const transition = result.state.transitions[messageIndex];
  const linkFields = processMessageStepLinkFields(rawInput, messageIndex, result);
  const publicFields = {
    messageIndex: BigInt(messageIndex),
    packedVals: result.publicFields.packedVals,
    coordPubKeyHash: result.publicFields.coordPubKeyHash,
    coordPrivKeyHash: linkFields.coordPrivKeyHash,
    previousMessageHash: result.derived.messageHashChain[messageIndex],
    nextMessageHash: result.derived.messageHashChain[messageIndex + 1],
    currentStateRoot: transition.input.currentStateRoot,
    newStateRoot: transition.derived.newStateRoot,
    currentStateCommitment: result.publicFields.currentStateCommitment,
    newStateCommitment: result.publicFields.newStateCommitment,
    activeStateRoot: result.state.derived.activeStateRoot,
    expectedPollId: result.publicFields.expectedPollId,
    encPubKeyHash: linkFields.encPubKeyHash,
    sharedKeyHash: linkFields.sharedKeyHash,
    signaturePubKeyHash: linkFields.signaturePubKeyHash,
    signatureR8Hash: linkFields.signatureR8Hash,
    packedCommandHash: linkFields.packedCommandHash,
    cmdSigS: linkFields.cmdSigS,
    isSignatureValid: linkFields.isSignatureValid,
  };
  const fields = {
    message_index: publicFields.messageIndex,
    packed_vals: splitObject(publicFields.packedVals, 'packedVals'),
    coord_pub_key_hash: splitObject(publicFields.coordPubKeyHash, 'coordPubKeyHash'),
    coord_priv_key_hash: splitObject(publicFields.coordPrivKeyHash, 'coordPrivKeyHash'),
    previous_message_hash: splitObject(
      publicFields.previousMessageHash,
      'previousMessageHash',
    ),
    next_message_hash: splitObject(publicFields.nextMessageHash, 'nextMessageHash'),
    current_state_root: splitObject(publicFields.currentStateRoot, 'currentStateRoot'),
    new_state_root: splitObject(publicFields.newStateRoot, 'newStateRoot'),
    current_state_commitment: splitObject(
      publicFields.currentStateCommitment,
      'currentStateCommitment',
    ),
    new_state_commitment: splitObject(publicFields.newStateCommitment, 'newStateCommitment'),
    active_state_root: splitObject(publicFields.activeStateRoot, 'activeStateRoot'),
    expected_poll_id: splitObject(publicFields.expectedPollId, 'expectedPollId'),
    enc_pub_key_hash: splitObject(publicFields.encPubKeyHash, 'encPubKeyHash'),
    shared_key_hash: splitObject(publicFields.sharedKeyHash, 'sharedKeyHash'),
    signature_pub_key_hash: splitObject(publicFields.signaturePubKeyHash, 'signaturePubKeyHash'),
    signature_r8_hash: splitObject(publicFields.signatureR8Hash, 'signatureR8Hash'),
    packed_command_hash: splitObject(publicFields.packedCommandHash, 'packedCommandHash'),
    cmd_sig_s: splitObject(publicFields.cmdSigS, 'cmdSigS'),
    is_signature_valid: splitObject(publicFields.isSignatureValid, 'isSignatureValid'),
  };
  const packedHashInputs = [
    transition.input.packedCommand[0],
    transition.input.packedCommand[1],
    transition.input.packedCommand[2],
    0n,
    0n,
  ];
  const publicOutput = canonicalProcessMessageStepCorePublicOutput(publicFields, result.params);

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        is_quadratic_cost: splitObject(result.derived.isQuadraticCost, 'isQuadraticCost'),
        num_signups: splitObject(result.derived.numSignUps, 'numSignUps'),
        max_vote_options: splitObject(result.derived.maxVoteOptions, 'maxVoteOptions'),
        enc_pub_key: splitVector2(rawInput.encPubKeys[messageIndex], 'encPubKey'),
        msg: splitVector10(rawInput.msgs[messageIndex], 'msg'),
        coord_priv_key: splitObject(rawInput.coordPrivKey, 'coordPrivKey'),
        current_state_salt: splitObject(rawInput.currentStateSalt, 'currentStateSalt'),
        new_state_salt: splitObject(rawInput.newStateSalt, 'newStateSalt'),
        coord_priv_key_hash: hash2Claim(
          rawInput.coordPrivKey,
          PROCESS_MESSAGE_COORD_PRIV_KEY_HASH_DOMAIN,
          publicFields.coordPrivKeyHash,
          'coordPrivKeyHash',
        ),
        current_state_commitment: hash2Claim(
          rawInput.currentStateRoot,
          rawInput.currentStateSalt,
          publicFields.currentStateCommitment,
          'currentStateCommitment',
        ),
        new_state_commitment: hash2Claim(
          rawInput.newStateRoot,
          rawInput.newStateSalt,
          publicFields.newStateCommitment,
          'newStateCommitment',
        ),
        enc_pub_key_hash: hash2Claim(
          rawInput.encPubKeys[messageIndex][0],
          rawInput.encPubKeys[messageIndex][1],
          publicFields.encPubKeyHash,
          'encPubKeyHash',
        ),
        shared_key_hash: hash2Claim(
          transition.input.sharedKey[0],
          transition.input.sharedKey[1],
          publicFields.sharedKeyHash,
          'sharedKeyHash',
        ),
        signature_pub_key_hash: hash2Claim(
          transition.input.stateLeaf[0],
          transition.input.stateLeaf[1],
          publicFields.signaturePubKeyHash,
          'signaturePubKeyHash',
        ),
        signature_r8_hash: hash2Claim(
          transition.input.cmdSigR8[0],
          transition.input.cmdSigR8[1],
          publicFields.signatureR8Hash,
          'signatureR8Hash',
        ),
        packed_command_hash: hash5Claim(
          packedHashInputs,
          publicFields.packedCommandHash,
          'packedCommandHash',
        ),
        message_hash: hash13Claim(
          messagePreimage(
            rawInput.msgs[messageIndex],
            rawInput.encPubKeys[messageIndex],
            publicFields.previousMessageHash,
          ),
          processMessageHash(
            rawInput.msgs[messageIndex],
            rawInput.encPubKeys[messageIndex],
            publicFields.previousMessageHash,
          ),
          `messageHash${messageIndex}`,
        ),
        state_decrypt: buildProcessOneStateDecryptWitness(transition, messageIndex),
        process_one: buildProcessOneStateTransitionWitnessFromEvaluation(transition),
      },
    },
    full_witness: {
      processMessages: rawInput,
      messageIndex,
    },
    public_output_labels: publicOutput.labels,
    public_output: publicOutput.decimalFelts,
  };
}

export function buildNativeCairoProcessMessageStepCoreInput(rawInput, messageIndex, evaluated) {
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const legacy = buildCairoProcessMessageStepCoreInput(rawInput, messageIndex, result);
  const transition = result.state.transitions[messageIndex];
  const linkFields = processMessageStepLinkFields(rawInput, messageIndex, result);
  const nativeMsgChain = nativeMessageHashChain(rawInput.msgs, rawInput.encPubKeys, rawInput.batchStartHash);
  const nativeContext = nativeProcessMessageTransitionContexts(result.state)[messageIndex];
  legacy.program_input.witness.process_one.state_leaf_path_0 = splitVector4(
    nativeContext.stateLeafPathElements[0],
    'nativeStateLeafPathElements[0]',
  );
  legacy.program_input.witness.process_one.state_leaf_path_1 = splitVector4(
    nativeContext.stateLeafPathElements[1],
    'nativeStateLeafPathElements[1]',
  );
  legacy.program_input.witness.process_one.current_vote_weight_path = splitVector4(
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
  const nativeWitness = buildNativeProcessMessageStepCoreWitness(legacy.program_input.witness);

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: nativeWitness,
    },
    full_witness: legacy.full_witness,
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
    state_decrypt: witness.state_decrypt,
    process_one: witness.process_one,
  };
}

export function buildCairoProcessMessagesStateTransitionInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessMessagesStateTransitions(rawInput);
  const witness = {
    current_state_root: splitObject(result.input.currentStateRoot, 'currentStateRoot'),
    new_state_root: splitObject(result.derived.newStateRoot, 'newStateRoot'),
    coord_priv_key: splitObject(result.input.coordPrivKey, 'coordPrivKey'),
    active_state_root: splitObject(result.input.activeStateRoot, 'activeStateRoot'),
    state_decrypt_0: buildProcessOneStateDecryptWitness(result.transitions[0], 0),
    state_decrypt_1: buildProcessOneStateDecryptWitness(result.transitions[1], 1),
    state_decrypt_2: buildProcessOneStateDecryptWitness(result.transitions[2], 2),
    state_decrypt_3: buildProcessOneStateDecryptWitness(result.transitions[3], 3),
    state_decrypt_4: buildProcessOneStateDecryptWitness(result.transitions[4], 4),
    process_one_0: buildProcessOneStateTransitionWitnessFromEvaluation(result.transitions[0]),
    process_one_1: buildProcessOneStateTransitionWitnessFromEvaluation(result.transitions[1]),
    process_one_2: buildProcessOneStateTransitionWitnessFromEvaluation(result.transitions[2]),
    process_one_3: buildProcessOneStateTransitionWitnessFromEvaluation(result.transitions[3]),
    process_one_4: buildProcessOneStateTransitionWitnessFromEvaluation(result.transitions[4]),
  };

  return {
    program_input: {
      witness,
    },
    expected_output: {
      new_state_root: splitObject(result.derived.newStateRoot, 'newStateRoot'),
    },
    full_witness: rawInput,
  };
}

export function buildCairoProcessMessagesStatefulInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const boundaryInput = buildCairoProcessMessagesInput(rawInput, result.boundary);
  const stateTransitionInput = buildCairoProcessMessagesStateTransitionInput(rawInput, result.state);

  return {
    fields: boundaryInput.fields,
    program_input: {
      fields: boundaryInput.program_input.fields,
      witness: {
        boundary: boundaryInput.program_input.witness,
        state_transition: stateTransitionInput.program_input.witness,
      },
    },
    full_witness: rawInput,
    public_output: result.publicOutput.decimalFelts,
  };
}

function ecdhInputForMessage(rawInput, messageIndex) {
  if (rawInput.ecdhInputs?.[messageIndex]) {
    return rawInput.ecdhInputs[messageIndex];
  }
  if (rawInput.coordPrivKey === undefined) {
    throw new Error('coordPrivKey is required to build stateful ECDH witness input');
  }
  const encPubKey = rawInput.encPubKeys[messageIndex];
  if (BigInt(encPubKey[0]) === 0n) {
    return {
      privKey: rawInput.coordPrivKey,
      pubKey: BABYJUB_BASE8.map((value) => value.toString()),
    };
  }
  return {
    privKey: rawInput.coordPrivKey,
    pubKey: encPubKey,
  };
}

function buildStatefulEcdhWitness(rawInput, result, boundaryInput, stateTransitionInput) {
  if (rawInput.coordPrivKey === undefined) {
    throw new Error('coordPrivKey is required to build stateful ECDH witness input');
  }
  const coordPubKeyCairoInput = buildCairoBabyjubScalarMulInput({
    scalar: rawInput.coordPrivKey,
    base: BABYJUB_BASE8.map((value) => value.toString()),
  });
  const [coordPubKeyX, coordPubKeyY] = coordPubKeyCairoInput.expected;
  if (
    coordPubKeyX !== BigInt(rawInput.coordPubKey[0]) ||
    coordPubKeyY !== BigInt(rawInput.coordPubKey[1])
  ) {
    throw new Error('coordPrivKey does not match coordPubKey');
  }

  const witness = {
    boundary: boundaryInput.program_input.witness,
    state_transition: stateTransitionInput.program_input.witness,
    coord_priv_key: splitObject(rawInput.coordPrivKey, 'coordPrivKey'),
    coord_pub_key: coordPubKeyCairoInput.program_input.witness,
  };

  for (let i = 0; i < 5; i += 1) {
    const ecdhCairoInput = buildCairoEcdhSharedKeyInput(ecdhInputForMessage(rawInput, i));
    if (BigInt(rawInput.encPubKeys[i][0]) !== 0n) {
      const [expectedX, expectedY] = ecdhCairoInput.expected;
      const transitionInput = result.state.transitions[i].input;
      if (expectedX !== transitionInput.sharedKey[0] || expectedY !== transitionInput.sharedKey[1]) {
        throw new Error(`ECDH shared key does not match ProcessOne ${i} sharedKey witness`);
      }
      if (
        expectedX !== BigInt(rawInput.processOneWitnesses[i].sharedKey[0]) ||
        expectedY !== BigInt(rawInput.processOneWitnesses[i].sharedKey[1])
      ) {
        throw new Error(`ECDH shared key does not match raw ProcessOne ${i} sharedKey`);
      }
    }
    witness[`ecdh_${i}`] = ecdhCairoInput.program_input.witness;
  }

  return witness;
}

function buildProcessOneSignatureInputForTransition(result, messageIndex) {
  const signatureCairoInput = buildProcessOneSignatureInput(result);
  if (signatureCairoInput.valid !== result.input.isSignatureValid) {
    throw new Error(`signature verification result does not match ProcessOne ${messageIndex}`);
  }
  return signatureCairoInput;
}

export function buildCairoProcessMessagesStatefulWithEcdhInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const boundaryInput = buildCairoProcessMessagesInput(rawInput, result.boundary);
  const stateTransitionInput = buildCairoProcessMessagesStateTransitionInput(rawInput, result.state);

  return {
    fields: boundaryInput.fields,
    program_input: {
      fields: boundaryInput.program_input.fields,
      witness: buildStatefulEcdhWitness(rawInput, result, boundaryInput, stateTransitionInput),
    },
    full_witness: rawInput,
    public_output: result.publicOutput.decimalFelts,
  };
}

function buildStatefulEcdhSignatureWitness(rawInput, result, boundaryInput, stateTransitionInput) {
  const witness = buildStatefulEcdhWitness(rawInput, result, boundaryInput, stateTransitionInput);
  for (let i = 0; i < 5; i += 1) {
    const signatureCairoInput = buildProcessOneSignatureInputForTransition(
      result.state.transitions[i],
      i,
    );
    witness[`signature_${i}`] = signatureCairoInput.program_input.witness;
  }
  return witness;
}

export function buildCairoProcessMessagesStatefulWithEcdhSignatureInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateProcessMessagesStateful(rawInput);
  const boundaryInput = buildCairoProcessMessagesInput(rawInput, result.boundary);
  const stateTransitionInput = buildCairoProcessMessagesStateTransitionInput(rawInput, result.state);

  return {
    fields: boundaryInput.fields,
    program_input: {
      fields: boundaryInput.program_input.fields,
      witness: buildStatefulEcdhSignatureWitness(
        rawInput,
        result,
        boundaryInput,
        stateTransitionInput,
      ),
    },
    full_witness: rawInput,
    public_output: result.publicOutput.decimalFelts,
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

function pushVector7(args, value) {
  pushU256(args, value.v0);
  pushU256(args, value.v1);
  pushU256(args, value.v2);
  pushU256(args, value.v3);
  pushU256(args, value.v4);
  pushU256(args, value.v5);
  pushU256(args, value.v6);
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

function pushSha256U256x8Claim(args, value) {
  pushVector8(args, value.inputs);
  pushU256(args, value.out);
}

function pushProcessMessagesFields(args, fields) {
  pushU256(args, fields.packed_vals);
  pushU256(args, fields.coord_pub_key_hash);
  pushU256(args, fields.batch_start_hash);
  pushU256(args, fields.batch_end_hash);
  pushU256(args, fields.current_state_commitment);
  pushU256(args, fields.new_state_commitment);
  pushU256(args, fields.deactivate_commitment);
  pushU256(args, fields.expected_poll_id);
  pushU256(args, fields.input_hash);
}

function pushProcessMessageStepFields(args, fields) {
  args.push(BigInt(fields.message_index));
  pushU256(args, fields.packed_vals);
  pushU256(args, fields.coord_pub_key_hash);
  pushU256(args, fields.previous_message_hash);
  pushU256(args, fields.next_message_hash);
  pushU256(args, fields.current_state_root);
  pushU256(args, fields.new_state_root);
  pushU256(args, fields.current_state_commitment);
  pushU256(args, fields.new_state_commitment);
  pushU256(args, fields.active_state_root);
  pushU256(args, fields.expected_poll_id);
}

function pushProcessMessageCoordKeyFields(args, fields) {
  pushU256(args, fields.coord_pub_key_hash);
  pushU256(args, fields.coord_priv_key_hash);
}

function pushProcessMessageEcdhFields(args, fields) {
  args.push(BigInt(fields.message_index));
  pushU256(args, fields.coord_priv_key_hash);
  pushU256(args, fields.enc_pub_key_hash);
  pushU256(args, fields.shared_key_hash);
}

function pushProcessMessageSignatureFields(args, fields) {
  args.push(BigInt(fields.message_index));
  pushU256(args, fields.pub_key_hash);
  pushU256(args, fields.r8_hash);
  pushU256(args, fields.packed_command_hash);
  pushU256(args, fields.cmd_sig_s);
  pushU256(args, fields.is_signature_valid);
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

function pushNativeProcessMessageSignatureFields(args, fields) {
  pushFelt(args, fields.message_index);
  pushFelt(args, fields.pub_key_hash);
  pushFelt(args, fields.r8_hash);
  pushFelt(args, fields.packed_command_hash);
  pushFelt(args, fields.cmd_sig_s_hash);
  pushFelt(args, fields.command_auth_hash);
  pushFelt(args, fields.is_signature_valid);
}

function pushProcessMessageStepCoreFields(args, fields) {
  args.push(BigInt(fields.message_index));
  pushU256(args, fields.packed_vals);
  pushU256(args, fields.coord_pub_key_hash);
  pushU256(args, fields.coord_priv_key_hash);
  pushU256(args, fields.previous_message_hash);
  pushU256(args, fields.next_message_hash);
  pushU256(args, fields.current_state_root);
  pushU256(args, fields.new_state_root);
  pushU256(args, fields.current_state_commitment);
  pushU256(args, fields.new_state_commitment);
  pushU256(args, fields.active_state_root);
  pushU256(args, fields.expected_poll_id);
  pushU256(args, fields.enc_pub_key_hash);
  pushU256(args, fields.shared_key_hash);
  pushU256(args, fields.signature_pub_key_hash);
  pushU256(args, fields.signature_r8_hash);
  pushU256(args, fields.packed_command_hash);
  pushU256(args, fields.cmd_sig_s);
  pushU256(args, fields.is_signature_valid);
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
  pushFelt(args, fields.signature_pub_key_hash);
  pushFelt(args, fields.signature_r8_hash);
  pushFelt(args, fields.packed_command_hash);
  pushFelt(args, fields.cmd_sig_s_hash);
  pushFelt(args, fields.command_auth_hash);
  pushFelt(args, fields.command_plaintext_binding_hash);
  pushFelt(args, fields.is_signature_valid);
}

function pushProcessMessagesWitness(args, witness) {
  pushU256(args, witness.is_quadratic_cost);
  pushU256(args, witness.num_signups);
  pushU256(args, witness.max_vote_options);
  pushVector2(args, witness.coord_pub_key);
  pushU256(args, witness.current_state_root);
  pushU256(args, witness.current_state_salt);
  pushU256(args, witness.new_state_root);
  pushU256(args, witness.new_state_salt);
  pushU256(args, witness.active_state_root);
  pushU256(args, witness.deactivate_root);
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
  pushHash2Claim(args, witness.hashes.current_state_commitment);
  pushHash2Claim(args, witness.hashes.new_state_commitment);
  pushHash2Claim(args, witness.hashes.deactivate_commitment);
  pushHash13Claim(args, witness.hashes.message_hash_0);
  pushHash13Claim(args, witness.hashes.message_hash_1);
  pushHash13Claim(args, witness.hashes.message_hash_2);
  pushHash13Claim(args, witness.hashes.message_hash_3);
  pushHash13Claim(args, witness.hashes.message_hash_4);
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

function pushElGamalDecryptWitness(args, witness) {
  pushBabyjubScalarMulWitness(args, witness.scalar_mul);
  pushVector2(args, witness.decrypted_point);
}

function pushProcessOneWithEcdhWitness(args, witness) {
  pushBabyjubScalarMulWitness(args, witness.ecdh);
  pushProcessOneStateTransitionWitness(args, witness.process_one);
}

function pushBabyjubPoseidonSignatureWitness(args, witness) {
  pushVector2(args, witness.pub_key_x2);
  pushVector2(args, witness.pub_key_x4);
  pushVector2(args, witness.pub_key_x8);
  pushBabyjubScalarMulWitness(args, witness.s_base8);
  pushBabyjubScalarMulWitness(args, witness.h_pub_key_x8);
  pushVector2(args, witness.right);
}

function pushProcessOneWithSignatureWitness(args, witness) {
  pushBabyjubPoseidonSignatureWitness(args, witness.signature);
  pushProcessOneStateTransitionWitness(args, witness.process_one);
}

function pushProcessOneWithEcdhSignatureWitness(args, witness) {
  pushBabyjubScalarMulWitness(args, witness.ecdh);
  pushBabyjubPoseidonSignatureWitness(args, witness.signature);
  pushProcessOneStateTransitionWitness(args, witness.process_one);
}

function pushProcessMessageStepWithEcdhSignatureWitness(args, witness) {
  pushU256(args, witness.is_quadratic_cost);
  pushU256(args, witness.num_signups);
  pushU256(args, witness.max_vote_options);
  pushVector2(args, witness.coord_pub_key);
  pushVector2(args, witness.enc_pub_key);
  pushVector10(args, witness.msg);
  pushU256(args, witness.coord_priv_key);
  pushU256(args, witness.current_state_salt);
  pushU256(args, witness.new_state_salt);
  pushBabyjubScalarMulWitness(args, witness.coord_pub_key_scalar_mul);
  pushHash2Claim(args, witness.coord_pub_key_hash);
  pushHash2Claim(args, witness.current_state_commitment);
  pushHash2Claim(args, witness.new_state_commitment);
  pushHash13Claim(args, witness.message_hash);
  pushElGamalDecryptWitness(args, witness.state_decrypt);
  pushBabyjubScalarMulWitness(args, witness.ecdh);
  pushBabyjubPoseidonSignatureWitness(args, witness.signature);
  pushProcessOneStateTransitionWitness(args, witness.process_one);
}

function pushProcessMessageCoordKeyWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.coord_pub_key);
  pushBabyjubScalarMulWitness(args, witness.coord_pub_key_scalar_mul);
  pushHash2Claim(args, witness.coord_pub_key_hash);
  pushHash2Claim(args, witness.coord_priv_key_hash);
}

function pushNativeProcessMessageCoordKeyWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.coord_pub_key);
}

function pushProcessMessageEcdhWitness(args, witness) {
  pushU256(args, witness.coord_priv_key);
  pushVector2(args, witness.enc_pub_key);
  pushBabyjubScalarMulWitness(args, witness.ecdh);
  pushHash2Claim(args, witness.coord_priv_key_hash);
  pushHash2Claim(args, witness.enc_pub_key_hash);
  pushHash2Claim(args, witness.shared_key_hash);
}

function pushProcessMessageSignatureWitness(args, witness) {
  pushVector2(args, witness.pub_key);
  pushVector2(args, witness.r8);
  pushU256(args, witness.s);
  pushVector3(args, witness.packed_command);
  pushBabyjubPoseidonSignatureWitness(args, witness.signature);
  pushHash2Claim(args, witness.pub_key_hash);
  pushHash2Claim(args, witness.r8_hash);
  pushHash5Claim(args, witness.packed_command_hash);
}

function pushNativeProcessMessageSignatureWitness(args, witness) {
  pushVector2(args, witness.pub_key);
  pushVector2(args, witness.r8);
  pushU256(args, witness.s);
  pushVector3(args, witness.packed_command);
  pushU256(args, witness.cmd_salt);
}

function pushProcessMessageStepCoreWitness(args, witness) {
  pushU256(args, witness.is_quadratic_cost);
  pushU256(args, witness.num_signups);
  pushU256(args, witness.max_vote_options);
  pushVector2(args, witness.enc_pub_key);
  pushVector10(args, witness.msg);
  pushU256(args, witness.coord_priv_key);
  pushU256(args, witness.current_state_salt);
  pushU256(args, witness.new_state_salt);
  pushHash2Claim(args, witness.coord_priv_key_hash);
  pushHash2Claim(args, witness.current_state_commitment);
  pushHash2Claim(args, witness.new_state_commitment);
  pushHash2Claim(args, witness.enc_pub_key_hash);
  pushHash2Claim(args, witness.shared_key_hash);
  pushHash2Claim(args, witness.signature_pub_key_hash);
  pushHash2Claim(args, witness.signature_r8_hash);
  pushHash5Claim(args, witness.packed_command_hash);
  pushHash13Claim(args, witness.message_hash);
  pushElGamalDecryptWitness(args, witness.state_decrypt);
  pushProcessOneStateTransitionWitness(args, witness.process_one);
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
  pushElGamalDecryptWitness(args, witness.state_decrypt);
  pushProcessOneStateTransitionWitness(args, witness.process_one);
}

function pushProcessMessagesStateTransitionWitness(args, witness) {
  pushU256(args, witness.current_state_root);
  pushU256(args, witness.new_state_root);
  pushU256(args, witness.coord_priv_key);
  pushU256(args, witness.active_state_root);
  pushElGamalDecryptWitness(args, witness.state_decrypt_0);
  pushElGamalDecryptWitness(args, witness.state_decrypt_1);
  pushElGamalDecryptWitness(args, witness.state_decrypt_2);
  pushElGamalDecryptWitness(args, witness.state_decrypt_3);
  pushElGamalDecryptWitness(args, witness.state_decrypt_4);
  pushProcessOneStateTransitionWitness(args, witness.process_one_0);
  pushProcessOneStateTransitionWitness(args, witness.process_one_1);
  pushProcessOneStateTransitionWitness(args, witness.process_one_2);
  pushProcessOneStateTransitionWitness(args, witness.process_one_3);
  pushProcessOneStateTransitionWitness(args, witness.process_one_4);
}

function pushProcessMessagesStatefulWitness(args, witness) {
  pushProcessMessagesWitness(args, witness.boundary);
  pushProcessMessagesStateTransitionWitness(args, witness.state_transition);
}

function pushProcessMessagesStatefulWithEcdhWitness(args, witness) {
  pushProcessMessagesWitness(args, witness.boundary);
  pushProcessMessagesStateTransitionWitness(args, witness.state_transition);
  pushU256(args, witness.coord_priv_key);
  pushBabyjubScalarMulWitness(args, witness.coord_pub_key);
  pushBabyjubScalarMulWitness(args, witness.ecdh_0);
  pushBabyjubScalarMulWitness(args, witness.ecdh_1);
  pushBabyjubScalarMulWitness(args, witness.ecdh_2);
  pushBabyjubScalarMulWitness(args, witness.ecdh_3);
  pushBabyjubScalarMulWitness(args, witness.ecdh_4);
}

function pushProcessMessagesStatefulWithEcdhSignatureWitness(args, witness) {
  pushProcessMessagesStatefulWithEcdhWitness(args, witness);
  pushBabyjubPoseidonSignatureWitness(args, witness.signature_0);
  pushBabyjubPoseidonSignatureWitness(args, witness.signature_1);
  pushBabyjubPoseidonSignatureWitness(args, witness.signature_2);
  pushBabyjubPoseidonSignatureWitness(args, witness.signature_3);
  pushBabyjubPoseidonSignatureWitness(args, witness.signature_4);
}

export function serializeCairoProcessMessagesExecutableArgs(cairoInput) {
  const args = [];
  pushProcessMessagesFields(args, cairoInput.program_input.fields);
  pushProcessMessagesWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessOneStateTransitionExecutableArgs(cairoInput) {
  const args = [];
  pushProcessOneStateTransitionWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessOneWithEcdhExecutableArgs(cairoInput) {
  const args = [];
  pushProcessOneWithEcdhWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessOneWithSignatureExecutableArgs(cairoInput) {
  const args = [];
  pushProcessOneWithSignatureWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessOneWithEcdhSignatureExecutableArgs(cairoInput) {
  const args = [];
  pushProcessOneWithEcdhSignatureWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessMessageStepWithEcdhSignatureExecutableArgs(cairoInput) {
  const args = [];
  pushProcessMessageStepFields(args, cairoInput.program_input.fields);
  pushProcessMessageStepWithEcdhSignatureWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessMessageCoordKeyExecutableArgs(cairoInput) {
  const args = [];
  pushProcessMessageCoordKeyFields(args, cairoInput.program_input.fields);
  pushProcessMessageCoordKeyWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessMessageEcdhExecutableArgs(cairoInput) {
  const args = [];
  pushProcessMessageEcdhFields(args, cairoInput.program_input.fields);
  pushProcessMessageEcdhWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessMessageSignatureExecutableArgs(cairoInput) {
  const args = [];
  pushProcessMessageSignatureFields(args, cairoInput.program_input.fields);
  pushProcessMessageSignatureWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
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

export function serializeNativeCairoProcessMessageSignatureExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessMessageSignatureFields(args, cairoInput.program_input.fields);
  pushNativeProcessMessageSignatureWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessMessageStepCoreExecutableArgs(cairoInput) {
  const args = [];
  pushProcessMessageStepCoreFields(args, cairoInput.program_input.fields);
  pushProcessMessageStepCoreWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoProcessMessageStepCoreExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessMessageStepCoreFields(args, cairoInput.program_input.fields);
  pushNativeProcessMessageStepCoreWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessMessagesStateTransitionExecutableArgs(cairoInput) {
  const args = [];
  pushProcessMessagesStateTransitionWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessMessagesStatefulExecutableArgs(cairoInput) {
  const args = [];
  pushProcessMessagesFields(args, cairoInput.program_input.fields);
  pushProcessMessagesStatefulWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessMessagesStatefulWithEcdhExecutableArgs(cairoInput) {
  const args = [];
  pushProcessMessagesFields(args, cairoInput.program_input.fields);
  pushProcessMessagesStatefulWithEcdhWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeCairoProcessMessagesStatefulWithEcdhSignatureExecutableArgs(cairoInput) {
  const args = [];
  pushProcessMessagesFields(args, cairoInput.program_input.fields);
  pushProcessMessagesStatefulWithEcdhSignatureWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}
