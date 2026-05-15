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

function buildNativeProcessMessagesBoundaryWitness(evaluated) {
  const witness = evaluated.nativeWitness;
  return {
    is_quadratic_cost: feltObject(witness.isQuadraticCost),
    num_signups: feltObject(witness.numSignUps),
    max_vote_options: feltObject(witness.maxVoteOptions),
    coord_pub_key: feltVector(witness.coordPubKey, 2, 'coordPubKey'),
    current_state_root: feltObject(witness.currentStateRoot),
    current_state_salt: feltObject(witness.currentStateSalt),
    new_state_root: feltObject(witness.newStateRoot),
    new_state_salt: feltObject(witness.newStateSalt),
    active_state_root: feltObject(witness.activeStateRoot),
    deactivate_root: feltObject(witness.deactivateRoot),
    expected_poll_id: feltObject(witness.expectedPollId),
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

export function buildNativeCairoProcessMessagesBoundaryInput(_rawInput, evaluated) {
  const fields = {
    packed_vals: feltObject(evaluated.publicFields.packedVals),
    coord_pub_key_hash: feltObject(evaluated.publicFields.coordPubKeyHash),
    batch_start_hash: feltObject(evaluated.publicFields.batchStartHash),
    batch_end_hash: feltObject(evaluated.publicFields.batchEndHash),
    current_state_commitment: feltObject(evaluated.publicFields.currentStateCommitment),
    new_state_commitment: feltObject(evaluated.publicFields.newStateCommitment),
    deactivate_commitment: feltObject(evaluated.publicFields.deactivateCommitment),
    expected_poll_id: feltObject(evaluated.publicFields.expectedPollId),
    input_hash: feltObject(evaluated.publicFields.inputHash),
  };

  return {
    fields,
    witness_summary: {
      current_state_root: feltObject(evaluated.nativeWitness.currentStateRoot),
      new_state_root: feltObject(evaluated.nativeWitness.newStateRoot),
      active_state_root: feltObject(evaluated.nativeWitness.activeStateRoot),
    },
    program_input: {
      fields,
      witness: buildNativeProcessMessagesBoundaryWitness(evaluated),
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

function pushNativeProcessMessagesBoundaryFields(args, fields) {
  pushFelt(args, fields.packed_vals);
  pushFelt(args, fields.coord_pub_key_hash);
  pushFelt(args, fields.batch_start_hash);
  pushFelt(args, fields.batch_end_hash);
  pushFelt(args, fields.current_state_commitment);
  pushFelt(args, fields.new_state_commitment);
  pushFelt(args, fields.deactivate_commitment);
  pushFelt(args, fields.expected_poll_id);
  pushFelt(args, fields.input_hash);
}

function pushNativeProcessMessagesBoundaryWitness(args, witness) {
  pushFelt(args, witness.is_quadratic_cost);
  pushFelt(args, witness.num_signups);
  pushFelt(args, witness.max_vote_options);
  pushFeltVector(args, witness.coord_pub_key, 2);
  pushFelt(args, witness.current_state_root);
  pushFelt(args, witness.current_state_salt);
  pushFelt(args, witness.new_state_root);
  pushFelt(args, witness.new_state_salt);
  pushFelt(args, witness.active_state_root);
  pushFelt(args, witness.deactivate_root);
  pushFelt(args, witness.expected_poll_id);
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

export function serializeNativeCairoProcessMessagesBoundaryExecutableArgs(cairoInput) {
  const args = [];
  pushNativeProcessMessagesBoundaryFields(args, cairoInput.program_input.fields);
  pushNativeProcessMessagesBoundaryWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(BigInt(value)));
}
