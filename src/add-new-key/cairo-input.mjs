import { bigintToHex, decimalize, splitU256ToU128 } from '../compat/encoding.mjs';
import {
  ADD_NEW_KEY_NATIVE_CIRCUIT_ID,
  ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN,
  ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN,
  NATIVE_PUBLIC_OUTPUT_VERSION,
  PUBLIC_OUTPUT_MAGIC,
  STARKNET_POSEIDON_HASH_SCHEME,
} from '../constants.mjs';
import { poseidonManyFelts } from '../integrity/hashes.mjs';
import {
  buildCairoBabyjubScalarMulInput,
  buildCairoEcdhSharedKeyInput,
} from '../compat/babyjub-cairo-input.mjs';
import { BABYJUB_BASE8 } from '../compat/babyjub.mjs';
import { toStarkFelt } from '../tally/native-tally-votes.mjs';
import { evaluateAddNewKey } from './add-new-key.mjs';

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

function nativeHashPoint(values, label) {
  if (!Array.isArray(values) || values.length !== 2) {
    throw new Error(`${label} must contain two values`);
  }
  return nativeHashFelts(values, label);
}

function nativeNullifier(oldPrivateKey, pollId) {
  return nativeHashFelts([
    ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN,
    oldPrivateKey,
    pollId,
  ], 'nullifier');
}

function nativeInputHash(fields) {
  return poseidonManyFelts([
    ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN,
    fields.deactivate_root_hash,
    fields.coord_pub_key_hash,
    fields.nullifier,
    fields.d1_hash,
    fields.d2_hash,
    fields.new_pub_key_hash,
    fields.poll_id,
  ]);
}

function nativeAddNewKeyPublicOutput(fields, params) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'hash_scheme',
    'state_tree_depth',
    'deactivate_tree_depth',
    'deactivate_root_hash',
    'coord_pub_key_hash',
    'nullifier',
    'd1_hash',
    'd2_hash',
    'new_pub_key_hash',
    'poll_id',
    'input_hash',
  ];
  const felts = [
    PUBLIC_OUTPUT_MAGIC,
    NATIVE_PUBLIC_OUTPUT_VERSION,
    ADD_NEW_KEY_NATIVE_CIRCUIT_ID,
    STARKNET_POSEIDON_HASH_SCHEME,
    BigInt(params.stateTreeDepth),
    BigInt(params.deactivateTreeDepth),
    fields.deactivate_root_hash,
    fields.coord_pub_key_hash,
    fields.nullifier,
    fields.d1_hash,
    fields.d2_hash,
    fields.new_pub_key_hash,
    fields.poll_id,
    fields.input_hash,
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

function splitVector9(values, label) {
  if (!Array.isArray(values) || values.length !== 9) {
    throw new Error(`${label} must contain nine values`);
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

function sha256U256x9Claim(inputs, out, label) {
  return {
    inputs: splitVector9(inputs, `${label}.inputs`),
    out: splitObject(out, `${label}.out`),
  };
}

function buildAddNewKeyFields(evaluated) {
  const fields = evaluated.publicFields;
  return {
    deactivate_root: splitObject(fields.deactivateRoot, 'deactivateRoot'),
    coord_pub_key_hash: splitObject(fields.coordPubKeyHash, 'coordPubKeyHash'),
    nullifier: splitObject(fields.nullifier, 'nullifier'),
    d1: splitVector2(fields.d1, 'd1'),
    d2: splitVector2(fields.d2, 'd2'),
    new_pub_key_hash: splitObject(fields.newPubKeyHash, 'newPubKeyHash'),
    poll_id: splitObject(fields.pollId, 'pollId'),
    input_hash: splitObject(fields.inputHash, 'inputHash'),
  };
}

function buildAddNewKeyWitness(rawInput, evaluated) {
  const input = evaluated.input;
  const ecdh = buildCairoEcdhSharedKeyInput({
    privKey: input.oldPrivateKey,
    pubKey: input.coordPubKey,
  });
  const randomBase8 = buildCairoBabyjubScalarMulInput({
    scalar: input.randomVal,
    base: BABYJUB_BASE8,
  });
  const randomCoordPubKey = buildCairoBabyjubScalarMulInput({
    scalar: input.randomVal,
    base: input.coordPubKey,
  });

  return {
    coord_pub_key: splitVector2(input.coordPubKey, 'coordPubKey'),
    deactivate_index: splitObject(input.deactivateIndex, 'deactivateIndex'),
    deactivate_leaf: splitObject(input.deactivateLeaf, 'deactivateLeaf'),
    c1: splitVector2(input.c1, 'c1'),
    c2: splitVector2(input.c2, 'c2'),
    random_val: splitObject(input.randomVal, 'randomVal'),
    deactivate_leaf_path_0: splitVector4(input.deactivateLeafPathElements[0], 'deactivateLeafPathElements[0]'),
    deactivate_leaf_path_1: splitVector4(input.deactivateLeafPathElements[1], 'deactivateLeafPathElements[1]'),
    deactivate_leaf_path_2: splitVector4(input.deactivateLeafPathElements[2], 'deactivateLeafPathElements[2]'),
    deactivate_leaf_path_3: splitVector4(input.deactivateLeafPathElements[3], 'deactivateLeafPathElements[3]'),
    old_private_key: splitObject(input.oldPrivateKey, 'oldPrivateKey'),
    new_pub_key: splitVector2(input.newPubKey, 'newPubKey'),
    poll_id: splitObject(input.pollId, 'pollId'),
    ecdh: ecdh.program_input.witness,
    random_base8: randomBase8.program_input.witness,
    random_coord_pub_key: randomCoordPubKey.program_input.witness,
    hashes: {
      coord_pub_key_hash: hash2Claim(
        input.coordPubKey[0],
        input.coordPubKey[1],
        evaluated.derived.coordPubKeyHash,
        'coordPubKeyHash',
      ),
      new_pub_key_hash: hash2Claim(
        input.newPubKey[0],
        input.newPubKey[1],
        evaluated.derived.newPubKeyHash,
        'newPubKeyHash',
      ),
      nullifier: hash2Claim(input.oldPrivateKey, input.pollId, evaluated.derived.nullifier, 'nullifier'),
      shared_key_hash: hash2Claim(
        evaluated.derived.sharedKey[0],
        evaluated.derived.sharedKey[1],
        evaluated.derived.sharedKeyHash,
        'sharedKeyHash',
      ),
      deactivate_leaf: hash5Claim(
        [...input.c1, ...input.c2, evaluated.derived.sharedKeyHash],
        evaluated.derived.deactivateLeaf,
        'deactivateLeaf',
      ),
      input_hash: sha256U256x9Claim(
        [
          input.deactivateRoot,
          evaluated.derived.coordPubKeyHash,
          input.nullifier,
          input.d1[0],
          input.d1[1],
          input.d2[0],
          input.d2[1],
          evaluated.derived.newPubKeyHash,
          input.pollId,
        ],
        input.inputHash,
        'inputHash',
      ),
    },
    full_witness: rawInput,
  };
}

export function buildCairoAddNewKeyInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateAddNewKey(rawInput);
  const fields = buildAddNewKeyFields(result);
  const witness = buildAddNewKeyWitness(rawInput, result);

  return {
    fields,
    program_input: {
      fields,
      witness,
    },
    full_witness: rawInput,
    public_output: result.publicOutput.decimalFelts,
  };
}

export function buildNativeCairoAddNewKeyInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateAddNewKey(rawInput);
  const legacy = buildCairoAddNewKeyInput(rawInput, result);
  const input = result.input;
  const publicFields = {
    deactivate_root_hash: nativeFelt(input.deactivateRoot, 'deactivateRoot'),
    coord_pub_key_hash: nativeHashPoint(input.coordPubKey, 'coordPubKey'),
    nullifier: nativeNullifier(input.oldPrivateKey, input.pollId),
    d1_hash: nativeHashPoint(input.d1, 'd1'),
    d2_hash: nativeHashPoint(input.d2, 'd2'),
    new_pub_key_hash: nativeHashPoint(input.newPubKey, 'newPubKey'),
    poll_id: input.pollId,
  };
  publicFields.input_hash = nativeInputHash(publicFields);
  const fields = {
    deactivate_root_hash: feltObject(publicFields.deactivate_root_hash),
    coord_pub_key_hash: feltObject(publicFields.coord_pub_key_hash),
    nullifier: feltObject(publicFields.nullifier),
    d1_hash: feltObject(publicFields.d1_hash),
    d2_hash: feltObject(publicFields.d2_hash),
    new_pub_key_hash: feltObject(publicFields.new_pub_key_hash),
    poll_id: feltObject(publicFields.poll_id),
    input_hash: feltObject(publicFields.input_hash),
  };
  const publicOutput = nativeAddNewKeyPublicOutput(publicFields, result.params);

  return {
    fields,
    publicFields,
    program_input: {
      fields,
      witness: {
        legacy: legacy.program_input.witness,
        d1: splitVector2(input.d1, 'd1'),
        d2: splitVector2(input.d2, 'd2'),
      },
    },
    full_witness: rawInput,
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

function pushVector9(args, value) {
  pushU256(args, value.v0);
  pushU256(args, value.v1);
  pushU256(args, value.v2);
  pushU256(args, value.v3);
  pushU256(args, value.v4);
  pushU256(args, value.v5);
  pushU256(args, value.v6);
  pushU256(args, value.v7);
  pushU256(args, value.v8);
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

function pushSha256U256x9Claim(args, value) {
  pushVector9(args, value.inputs);
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

function pushAddNewKeyFields(args, fields) {
  pushU256(args, fields.deactivate_root);
  pushU256(args, fields.coord_pub_key_hash);
  pushU256(args, fields.nullifier);
  pushVector2(args, fields.d1);
  pushVector2(args, fields.d2);
  pushU256(args, fields.new_pub_key_hash);
  pushU256(args, fields.poll_id);
  pushU256(args, fields.input_hash);
}

function pushNativeAddNewKeyFields(args, fields) {
  pushFelt(args, fields.deactivate_root_hash);
  pushFelt(args, fields.coord_pub_key_hash);
  pushFelt(args, fields.nullifier);
  pushFelt(args, fields.d1_hash);
  pushFelt(args, fields.d2_hash);
  pushFelt(args, fields.new_pub_key_hash);
  pushFelt(args, fields.poll_id);
  pushFelt(args, fields.input_hash);
}

function pushAddNewKeyWitness(args, witness) {
  pushVector2(args, witness.coord_pub_key);
  pushU256(args, witness.deactivate_index);
  pushU256(args, witness.deactivate_leaf);
  pushVector2(args, witness.c1);
  pushVector2(args, witness.c2);
  pushU256(args, witness.random_val);
  pushVector4(args, witness.deactivate_leaf_path_0);
  pushVector4(args, witness.deactivate_leaf_path_1);
  pushVector4(args, witness.deactivate_leaf_path_2);
  pushVector4(args, witness.deactivate_leaf_path_3);
  pushU256(args, witness.old_private_key);
  pushVector2(args, witness.new_pub_key);
  pushU256(args, witness.poll_id);
  pushBabyjubScalarMulWitness(args, witness.ecdh);
  pushBabyjubScalarMulWitness(args, witness.random_base8);
  pushBabyjubScalarMulWitness(args, witness.random_coord_pub_key);
  pushHash2Claim(args, witness.hashes.coord_pub_key_hash);
  pushHash2Claim(args, witness.hashes.new_pub_key_hash);
  pushHash2Claim(args, witness.hashes.nullifier);
  pushHash2Claim(args, witness.hashes.shared_key_hash);
  pushHash5Claim(args, witness.hashes.deactivate_leaf);
  pushSha256U256x9Claim(args, witness.hashes.input_hash);
}

function pushNativeAddNewKeyWitness(args, witness) {
  pushAddNewKeyWitness(args, witness.legacy);
  pushVector2(args, witness.d1);
  pushVector2(args, witness.d2);
}

export function serializeCairoAddNewKeyExecutableArgs(cairoInput) {
  const args = [];
  pushAddNewKeyFields(args, cairoInput.program_input.fields);
  pushAddNewKeyWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}

export function serializeNativeCairoAddNewKeyExecutableArgs(cairoInput) {
  const args = [];
  pushNativeAddNewKeyFields(args, cairoInput.program_input.fields);
  pushNativeAddNewKeyWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}
