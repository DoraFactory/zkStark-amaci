import { bigintToHex, decimalize, splitU256ToU128 } from '../encoding.mjs';
import {
  ADD_NEW_KEY_NATIVE_CIRCUIT_ID,
  ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN,
  ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN,
  ADD_NEW_KEY_NATIVE_NULLIFIER_DOMAIN,
  ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN,
  NATIVE_PUBLIC_OUTPUT_VERSION,
  PUBLIC_OUTPUT_MAGIC,
  STARKNET_POSEIDON_HASH_SCHEME,
} from '../constants.mjs';
import { poseidonManyFelts } from '../integrity/hashes.mjs';
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

function nativeHash5(values, label) {
  if (!Array.isArray(values) || values.length !== 5) {
    throw new Error(`${label} must contain five values`);
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

function nativeDeactivateLeafHash(c1Hash, c2Hash, sharedKeyHash) {
  return nativeHashFelts(
    [ADD_NEW_KEY_NATIVE_DEACTIVATE_LEAF_DOMAIN, c1Hash, c2Hash, sharedKeyHash],
    'deactivateLeaf',
  );
}

function nativeRerandomizeBindingHash(coordPubKeyHash, c1Hash, c2Hash, d1Hash, d2Hash) {
  return nativeHashFelts(
    [ADD_NEW_KEY_NATIVE_RERANDOMIZE_DOMAIN, coordPubKeyHash, c1Hash, c2Hash, d1Hash, d2Hash],
    'rerandomizeBinding',
  );
}

function nativePathInputs(leaf, pathElements, index, label) {
  if (!Array.isArray(pathElements) || pathElements.length !== 4) {
    throw new Error(`${label} must contain four path elements`);
  }
  if (index < 0 || index > 4) {
    throw new Error(`${label} path index out of range`);
  }
  const values = pathElements.map((value, valueIndex) => toStarkFelt(value, `${label}[${valueIndex}]`));
  values.splice(index, 0, leaf);
  return values;
}

function nativeQuinaryInclusionRoot(leaf, path, index, label) {
  if (!Array.isArray(path) || path.length !== 4) {
    throw new Error(`${label} must contain four levels`);
  }
  const parsedIndex = Number(index);
  if (!Number.isInteger(parsedIndex) || parsedIndex < 0 || parsedIndex >= 5 ** 4) {
    throw new Error(`${label} index out of range`);
  }
  let current = leaf;
  for (let level = 0; level < 4; level += 1) {
    const position = Math.floor(parsedIndex / 5 ** level) % 5;
    current = nativeHash5(nativePathInputs(current, path[level], position, `${label}[${level}]`), `${label}.level${level}`);
  }
  return current;
}

function nativeInputHash(fields) {
  return poseidonManyFelts([
    ADD_NEW_KEY_NATIVE_INPUT_HASH_DOMAIN,
    fields.deactivate_root_hash,
    fields.coord_pub_key_hash,
    fields.nullifier,
    fields.c1_hash,
    fields.c2_hash,
    fields.shared_key_hash,
    fields.deactivate_leaf_hash,
    fields.d1_hash,
    fields.d2_hash,
    fields.rerandomize_binding_hash,
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
    'c1_hash',
    'c2_hash',
    'shared_key_hash',
    'deactivate_leaf_hash',
    'd1_hash',
    'd2_hash',
    'rerandomize_binding_hash',
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
    fields.c1_hash,
    fields.c2_hash,
    fields.shared_key_hash,
    fields.deactivate_leaf_hash,
    fields.d1_hash,
    fields.d2_hash,
    fields.rerandomize_binding_hash,
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

export function buildNativeCairoAddNewKeyInput(rawInput, evaluated) {
  const result = evaluated ?? evaluateAddNewKey(rawInput);
  const input = result.input;
  const coordPubKeyHash = nativeHashPoint(input.coordPubKey, 'coordPubKey');
  const c1Hash = nativeHashPoint(input.c1, 'c1');
  const c2Hash = nativeHashPoint(input.c2, 'c2');
  const sharedKeyHash = nativeHashPoint(result.derived.sharedKey, 'sharedKey');
  const deactivateLeafHash = nativeDeactivateLeafHash(c1Hash, c2Hash, sharedKeyHash);
  const d1Hash = nativeHashPoint(input.d1, 'd1');
  const d2Hash = nativeHashPoint(input.d2, 'd2');
  const publicFields = {
    deactivate_root_hash: nativeQuinaryInclusionRoot(
      deactivateLeafHash,
      input.deactivateLeafPathElements,
      input.deactivateIndex,
      'deactivateLeafPath',
    ),
    coord_pub_key_hash: coordPubKeyHash,
    nullifier: nativeNullifier(input.oldPrivateKey, input.pollId),
    c1_hash: c1Hash,
    c2_hash: c2Hash,
    shared_key_hash: sharedKeyHash,
    deactivate_leaf_hash: deactivateLeafHash,
    d1_hash: d1Hash,
    d2_hash: d2Hash,
    rerandomize_binding_hash: nativeRerandomizeBindingHash(coordPubKeyHash, c1Hash, c2Hash, d1Hash, d2Hash),
    new_pub_key_hash: nativeHashPoint(input.newPubKey, 'newPubKey'),
    poll_id: input.pollId,
  };
  publicFields.input_hash = nativeInputHash(publicFields);
  const fields = {
    deactivate_root_hash: feltObject(publicFields.deactivate_root_hash),
    coord_pub_key_hash: feltObject(publicFields.coord_pub_key_hash),
    nullifier: feltObject(publicFields.nullifier),
    c1_hash: feltObject(publicFields.c1_hash),
    c2_hash: feltObject(publicFields.c2_hash),
    shared_key_hash: feltObject(publicFields.shared_key_hash),
    deactivate_leaf_hash: feltObject(publicFields.deactivate_leaf_hash),
    d1_hash: feltObject(publicFields.d1_hash),
    d2_hash: feltObject(publicFields.d2_hash),
    rerandomize_binding_hash: feltObject(publicFields.rerandomize_binding_hash),
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
        coord_pub_key: splitVector2(input.coordPubKey, 'coordPubKey'),
        deactivate_index: splitObject(input.deactivateIndex, 'deactivateIndex'),
        c1: splitVector2(input.c1, 'c1'),
        c2: splitVector2(input.c2, 'c2'),
        shared_key: splitVector2(result.derived.sharedKey, 'sharedKey'),
        random_val: splitObject(input.randomVal, 'randomVal'),
        deactivate_leaf_path_0: splitVector4(input.deactivateLeafPathElements[0], 'deactivateLeafPathElements[0]'),
        deactivate_leaf_path_1: splitVector4(input.deactivateLeafPathElements[1], 'deactivateLeafPathElements[1]'),
        deactivate_leaf_path_2: splitVector4(input.deactivateLeafPathElements[2], 'deactivateLeafPathElements[2]'),
        deactivate_leaf_path_3: splitVector4(input.deactivateLeafPathElements[3], 'deactivateLeafPathElements[3]'),
        old_private_key: splitObject(input.oldPrivateKey, 'oldPrivateKey'),
        new_pub_key: splitVector2(input.newPubKey, 'newPubKey'),
        poll_id: splitObject(input.pollId, 'pollId'),
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

function pushNativeAddNewKeyFields(args, fields) {
  pushFelt(args, fields.deactivate_root_hash);
  pushFelt(args, fields.coord_pub_key_hash);
  pushFelt(args, fields.nullifier);
  pushFelt(args, fields.c1_hash);
  pushFelt(args, fields.c2_hash);
  pushFelt(args, fields.shared_key_hash);
  pushFelt(args, fields.deactivate_leaf_hash);
  pushFelt(args, fields.d1_hash);
  pushFelt(args, fields.d2_hash);
  pushFelt(args, fields.rerandomize_binding_hash);
  pushFelt(args, fields.new_pub_key_hash);
  pushFelt(args, fields.poll_id);
  pushFelt(args, fields.input_hash);
}

function pushNativeAddNewKeyWitness(args, witness) {
  pushVector2(args, witness.coord_pub_key);
  pushU256(args, witness.deactivate_index);
  pushVector2(args, witness.c1);
  pushVector2(args, witness.c2);
  pushVector2(args, witness.shared_key);
  pushU256(args, witness.random_val);
  pushVector4(args, witness.deactivate_leaf_path_0);
  pushVector4(args, witness.deactivate_leaf_path_1);
  pushVector4(args, witness.deactivate_leaf_path_2);
  pushVector4(args, witness.deactivate_leaf_path_3);
  pushU256(args, witness.old_private_key);
  pushVector2(args, witness.new_pub_key);
  pushU256(args, witness.poll_id);
  pushVector2(args, witness.d1);
  pushVector2(args, witness.d2);
}

export function serializeNativeCairoAddNewKeyExecutableArgs(cairoInput) {
  const args = [];
  pushNativeAddNewKeyFields(args, cairoInput.program_input.fields);
  pushNativeAddNewKeyWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(value));
}
