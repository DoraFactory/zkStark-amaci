import { bigintToHex } from './compat/encoding.mjs';

function feltObject(value) {
  return value.toString();
}

function feltVector(values, expected, label) {
  if (!Array.isArray(values) || values.length !== expected) {
    throw new Error(`${label} must contain ${expected} values`);
  }
  return Object.fromEntries(values.map((value, index) => [`v${index}`, feltObject(value)]));
}

function buildNativeTallyWitness(evaluated) {
  const witness = evaluated.nativeWitness;
  return {
    state_root: feltObject(witness.stateRoot),
    state_salt: feltObject(witness.stateSalt),
    num_signups: feltObject(witness.numSignUps),
    batch_num: feltObject(witness.batchNum),
    state_leaf_0: feltVector(witness.stateLeaves[0], 10, 'stateLeaf[0]'),
    state_leaf_1: feltVector(witness.stateLeaves[1], 10, 'stateLeaf[1]'),
    state_leaf_2: feltVector(witness.stateLeaves[2], 10, 'stateLeaf[2]'),
    state_leaf_3: feltVector(witness.stateLeaves[3], 10, 'stateLeaf[3]'),
    state_leaf_4: feltVector(witness.stateLeaves[4], 10, 'stateLeaf[4]'),
    state_path_elements: feltVector(witness.statePathElements, 4, 'statePathElements'),
    votes_0: feltVector(witness.votes[0], 5, 'votes[0]'),
    votes_1: feltVector(witness.votes[1], 5, 'votes[1]'),
    votes_2: feltVector(witness.votes[2], 5, 'votes[2]'),
    votes_3: feltVector(witness.votes[3], 5, 'votes[3]'),
    votes_4: feltVector(witness.votes[4], 5, 'votes[4]'),
    current_results: feltVector(witness.currentResults, 5, 'currentResults'),
    current_results_root_salt: feltObject(witness.currentResultsRootSalt),
    new_results_root_salt: feltObject(witness.newResultsRootSalt),
  };
}

export function buildNativeCairoTallyInput(_rawInput, evaluated) {
  const fields = {
    packed_vals: feltObject(evaluated.publicFields.packedVals),
    state_commitment: feltObject(evaluated.publicFields.stateCommitment),
    current_tally_commitment: feltObject(evaluated.publicFields.currentTallyCommitment),
    new_tally_commitment: feltObject(evaluated.publicFields.newTallyCommitment),
    input_hash: feltObject(evaluated.publicFields.inputHash),
  };

  return {
    fields,
    witness_summary: {
      state_root: feltObject(evaluated.nativeWitness.stateRoot),
      state_salt: feltObject(evaluated.nativeWitness.stateSalt),
      new_results_root_salt: feltObject(evaluated.nativeWitness.newResultsRootSalt),
    },
    program_input: {
      fields,
      witness: buildNativeTallyWitness(evaluated),
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

function pushNativeTallyPublicFields(args, fields) {
  pushFelt(args, fields.packed_vals);
  pushFelt(args, fields.state_commitment);
  pushFelt(args, fields.current_tally_commitment);
  pushFelt(args, fields.new_tally_commitment);
  pushFelt(args, fields.input_hash);
}

function pushNativeTallyWitness(args, witness) {
  pushFelt(args, witness.state_root);
  pushFelt(args, witness.state_salt);
  pushFelt(args, witness.num_signups);
  pushFelt(args, witness.batch_num);
  pushFeltVector(args, witness.state_leaf_0, 10);
  pushFeltVector(args, witness.state_leaf_1, 10);
  pushFeltVector(args, witness.state_leaf_2, 10);
  pushFeltVector(args, witness.state_leaf_3, 10);
  pushFeltVector(args, witness.state_leaf_4, 10);
  pushFeltVector(args, witness.state_path_elements, 4);
  pushFeltVector(args, witness.votes_0, 5);
  pushFeltVector(args, witness.votes_1, 5);
  pushFeltVector(args, witness.votes_2, 5);
  pushFeltVector(args, witness.votes_3, 5);
  pushFeltVector(args, witness.votes_4, 5);
  pushFeltVector(args, witness.current_results, 5);
  pushFelt(args, witness.current_results_root_salt);
  pushFelt(args, witness.new_results_root_salt);
}

export function serializeNativeCairoTallyExecutableArgs(cairoInput) {
  const args = [];
  pushNativeTallyPublicFields(args, cairoInput.program_input.fields);
  pushNativeTallyWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(BigInt(value)));
}
