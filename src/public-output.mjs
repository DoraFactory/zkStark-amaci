import {
  PUBLIC_OUTPUT_MAGIC,
  PUBLIC_OUTPUT_VERSION,
  SMALL_TALLY_PARAMS,
  TALLY_VOTES_CIRCUIT_ID,
} from './constants.mjs';
import { decimalize, splitU256ToU128 } from './compat/encoding.mjs';

function pushU256(output, labels, name, value) {
  const { low, high } = splitU256ToU128(value, name);
  labels.push(`${name}_low128`, `${name}_high128`);
  output.push(low, high);
}

export function canonicalTallyPublicOutput(fields, params = SMALL_TALLY_PARAMS) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'state_tree_depth',
    'int_state_tree_depth',
    'vote_option_tree_depth',
  ];
  const output = [
    PUBLIC_OUTPUT_MAGIC,
    PUBLIC_OUTPUT_VERSION,
    TALLY_VOTES_CIRCUIT_ID,
    BigInt(params.stateTreeDepth),
    BigInt(params.intStateTreeDepth),
    BigInt(params.voteOptionTreeDepth),
  ];

  pushU256(output, labels, 'packed_vals', fields.packedVals);
  pushU256(output, labels, 'state_commitment', fields.stateCommitment);
  pushU256(output, labels, 'current_tally_commitment', fields.currentTallyCommitment);
  pushU256(output, labels, 'new_tally_commitment', fields.newTallyCommitment);
  pushU256(output, labels, 'input_hash', fields.inputHash);

  return {
    labels,
    felts: output,
    decimalFelts: output.map(decimalize),
  };
}

