import { bigintToHex } from '../compat/encoding.mjs';

function feltObject(value) {
  return value.toString();
}

function feltVector(values, expected, label) {
  if (!Array.isArray(values) || values.length !== expected) {
    throw new Error(`${label} must contain ${expected} values`);
  }
  return Object.fromEntries(values.map((value, index) => [`v${index}`, feltObject(value)]));
}

function buildNativeProcessDeactivateBoundaryWitness(evaluated) {
  const witness = evaluated.nativeWitness;
  return {
    coord_pub_key: feltVector(witness.coordPubKey, 2, 'coordPubKey'),
    current_active_state_root: feltObject(witness.currentActiveStateRoot),
    current_deactivate_root: feltObject(witness.currentDeactivateRoot),
    new_active_state_root: feltObject(witness.newActiveStateRoot),
    msg_0: feltVector(witness.msgs[0], 10, 'msgs[0]'),
    msg_1: feltVector(witness.msgs[1], 10, 'msgs[1]'),
    msg_2: feltVector(witness.msgs[2], 10, 'msgs[2]'),
    msg_3: feltVector(witness.msgs[3], 10, 'msgs[3]'),
    msg_4: feltVector(witness.msgs[4], 10, 'msgs[4]'),
    enc_pub_key_0: feltVector(witness.encPubKeys[0], 2, 'encPubKeys[0]'),
    enc_pub_key_1: feltVector(witness.encPubKeys[1], 2, 'encPubKeys[1]'),
    enc_pub_key_2: feltVector(witness.encPubKeys[2], 2, 'encPubKeys[2]'),
    enc_pub_key_3: feltVector(witness.encPubKeys[3], 2, 'encPubKeys[3]'),
    enc_pub_key_4: feltVector(witness.encPubKeys[4], 2, 'encPubKeys[4]'),
  };
}

export function buildNativeCairoProcessDeactivateBoundaryInput(_rawInput, evaluated) {
  const fields = {
    new_deactivate_root: feltObject(evaluated.publicFields.newDeactivateRoot),
    coord_pub_key_hash: feltObject(evaluated.publicFields.coordPubKeyHash),
    batch_start_hash: feltObject(evaluated.publicFields.batchStartHash),
    batch_end_hash: feltObject(evaluated.publicFields.batchEndHash),
    current_deactivate_commitment: feltObject(evaluated.publicFields.currentDeactivateCommitment),
    new_deactivate_commitment: feltObject(evaluated.publicFields.newDeactivateCommitment),
    current_state_root: feltObject(evaluated.publicFields.currentStateRoot),
    expected_poll_id: feltObject(evaluated.publicFields.expectedPollId),
    input_hash: feltObject(evaluated.publicFields.inputHash),
  };

  return {
    fields,
    witness_summary: {
      current_active_state_root: feltObject(evaluated.nativeWitness.currentActiveStateRoot),
      current_deactivate_root: feltObject(evaluated.nativeWitness.currentDeactivateRoot),
      new_active_state_root: feltObject(evaluated.nativeWitness.newActiveStateRoot),
    },
    program_input: {
      fields,
      witness: buildNativeProcessDeactivateBoundaryWitness(evaluated),
    },
    public_output_labels: evaluated.publicOutput.labels,
    public_output: evaluated.publicOutput.decimalFelts,
  };
}

function pushFelt(args, value) {
  args.push(value);
}

function pushFeltVector(args, value, expected) {
  for (let index = 0; index < expected; index += 1) {
    pushFelt(args, value[`v${index}`]);
  }
}

function pushNativeProcessDeactivateBoundaryFields(args, fields) {
  pushFelt(args, fields.new_deactivate_root);
  pushFelt(args, fields.coord_pub_key_hash);
  pushFelt(args, fields.batch_start_hash);
  pushFelt(args, fields.batch_end_hash);
  pushFelt(args, fields.current_deactivate_commitment);
  pushFelt(args, fields.new_deactivate_commitment);
  pushFelt(args, fields.current_state_root);
  pushFelt(args, fields.expected_poll_id);
  pushFelt(args, fields.input_hash);
}

function pushNativeProcessDeactivateBoundaryWitness(args, witness) {
  pushFeltVector(args, witness.coord_pub_key, 2);
  pushFelt(args, witness.current_active_state_root);
  pushFelt(args, witness.current_deactivate_root);
  pushFelt(args, witness.new_active_state_root);
  pushFeltVector(args, witness.msg_0, 10);
  pushFeltVector(args, witness.msg_1, 10);
  pushFeltVector(args, witness.msg_2, 10);
  pushFeltVector(args, witness.msg_3, 10);
  pushFeltVector(args, witness.msg_4, 10);
  pushFeltVector(args, witness.enc_pub_key_0, 2);
  pushFeltVector(args, witness.enc_pub_key_1, 2);
  pushFeltVector(args, witness.enc_pub_key_2, 2);
  pushFeltVector(args, witness.enc_pub_key_3, 2);
  pushFeltVector(args, witness.enc_pub_key_4, 2);
}

export function serializeNativeCairoProcessDeactivateBoundaryExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessDeactivateBoundaryFields(args, cairoInput.program_input.fields);
  pushNativeProcessDeactivateBoundaryWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(BigInt(value)));
}
