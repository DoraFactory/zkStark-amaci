import { bigintToHex, splitU256ToU128 } from './compat/encoding.mjs';
import { hash5, hashLeftRight } from './compat/poseidon.mjs';

function splitObject(value, label) {
  const { low, high } = splitU256ToU128(value, label);
  return {
    low: low.toString(),
    high: high.toString(),
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
  if (!Array.isArray(inputs) || inputs.length !== 10) {
    throw new Error(`${label}.inputs must contain ten values`);
  }
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

function sha256U256x4Claim(inputs, out, label) {
  return {
    inputs: splitVector4(inputs, `${label}.inputs`),
    out: splitObject(out, `${label}.out`),
  };
}

function statePathInputs(stateSubroot, statePathElements, batchNum) {
  const path = statePathElements.map(BigInt);
  const subroot = BigInt(stateSubroot);
  const idx = Number(batchNum);
  if (!Number.isInteger(idx) || idx < 0 || idx > 4) {
    throw new Error(`batchNum must be between 0 and 4 for TallyVotes(2,1,1), got ${batchNum}`);
  }

  const inputs = [];
  let pathCursor = 0;
  for (let i = 0; i < 5; i += 1) {
    if (i === idx) {
      inputs.push(subroot);
    } else {
      inputs.push(path[pathCursor]);
      pathCursor += 1;
    }
  }
  return inputs;
}

function buildCairoProgramWitness(rawInput, evaluated) {
  const { numSignUps, batchNum } = evaluated.derived;
  const zeroVoteInputs = [0n, 0n, 0n, 0n, 0n];
  const stateRootPathInputs = statePathInputs(
    evaluated.derived.stateSubroot,
    rawInput.statePathElements[0],
    batchNum,
  );

  return {
    state_root: splitObject(BigInt(rawInput.stateRoot), 'stateRoot'),
    state_salt: splitObject(BigInt(rawInput.stateSalt), 'stateSalt'),
    num_signups: splitObject(numSignUps, 'numSignUps'),
    batch_num: splitObject(batchNum, 'batchNum'),
    state_leaf_0: splitVector10(rawInput.stateLeaf[0], 'stateLeaf[0]'),
    state_leaf_1: splitVector10(rawInput.stateLeaf[1], 'stateLeaf[1]'),
    state_leaf_2: splitVector10(rawInput.stateLeaf[2], 'stateLeaf[2]'),
    state_leaf_3: splitVector10(rawInput.stateLeaf[3], 'stateLeaf[3]'),
    state_leaf_4: splitVector10(rawInput.stateLeaf[4], 'stateLeaf[4]'),
    state_path_elements: splitVector4(rawInput.statePathElements[0], 'statePathElements[0]'),
    votes_0: splitVector5(rawInput.votes[0], 'votes[0]'),
    votes_1: splitVector5(rawInput.votes[1], 'votes[1]'),
    votes_2: splitVector5(rawInput.votes[2], 'votes[2]'),
    votes_3: splitVector5(rawInput.votes[3], 'votes[3]'),
    votes_4: splitVector5(rawInput.votes[4], 'votes[4]'),
    current_results: splitVector5(rawInput.currentResults, 'currentResults'),
    current_results_root_salt: splitObject(
      BigInt(rawInput.currentResultsRootSalt),
      'currentResultsRootSalt',
    ),
    new_results_root_salt: splitObject(BigInt(rawInput.newResultsRootSalt), 'newResultsRootSalt'),
    hashes: {
      state_commitment: hash2Claim(
        rawInput.stateRoot,
        rawInput.stateSalt,
        evaluated.publicFields.stateCommitment,
        'stateCommitment',
      ),
      input_hash: sha256U256x4Claim(
        [
          evaluated.publicFields.packedVals,
          evaluated.publicFields.stateCommitment,
          evaluated.publicFields.currentTallyCommitment,
          evaluated.publicFields.newTallyCommitment,
        ],
        evaluated.publicFields.inputHash,
        'inputHash',
      ),
      state_leaf_0: hash10Claim(rawInput.stateLeaf[0], evaluated.derived.stateLeafHashes[0], 'stateLeaf0'),
      state_leaf_1: hash10Claim(rawInput.stateLeaf[1], evaluated.derived.stateLeafHashes[1], 'stateLeaf1'),
      state_leaf_2: hash10Claim(rawInput.stateLeaf[2], evaluated.derived.stateLeafHashes[2], 'stateLeaf2'),
      state_leaf_3: hash10Claim(rawInput.stateLeaf[3], evaluated.derived.stateLeafHashes[3], 'stateLeaf3'),
      state_leaf_4: hash10Claim(rawInput.stateLeaf[4], evaluated.derived.stateLeafHashes[4], 'stateLeaf4'),
      state_subroot: hash5Claim(
        evaluated.derived.stateLeafHashes,
        evaluated.derived.stateSubroot,
        'stateSubroot',
      ),
      state_root_from_path: hash5Claim(
        stateRootPathInputs,
        rawInput.stateRoot,
        'stateRootFromPath',
      ),
      vote_zero_root: hash5Claim(zeroVoteInputs, evaluated.derived.voteZeroRoot, 'voteZeroRoot'),
      vote_root_0: hash5Claim(rawInput.votes[0], evaluated.derived.voteRoots[0], 'voteRoot0'),
      vote_root_1: hash5Claim(rawInput.votes[1], evaluated.derived.voteRoots[1], 'voteRoot1'),
      vote_root_2: hash5Claim(rawInput.votes[2], evaluated.derived.voteRoots[2], 'voteRoot2'),
      vote_root_3: hash5Claim(rawInput.votes[3], evaluated.derived.voteRoots[3], 'voteRoot3'),
      vote_root_4: hash5Claim(rawInput.votes[4], evaluated.derived.voteRoots[4], 'voteRoot4'),
      current_results_root: hash5Claim(
        rawInput.currentResults,
        evaluated.derived.currentResultsRoot,
        'currentResultsRoot',
      ),
      current_tally_commitment: hash2Claim(
        evaluated.derived.currentResultsRoot,
        rawInput.currentResultsRootSalt,
        evaluated.derived.currentResultsCommitment,
        'currentTallyCommitment',
      ),
      new_results_root: hash5Claim(evaluated.derived.newResults, evaluated.derived.newResultsRoot, 'newResultsRoot'),
      new_tally_commitment: hash2Claim(
        evaluated.derived.newResultsRoot,
        rawInput.newResultsRootSalt,
        evaluated.derived.newTallyCommitment,
        'newTallyCommitment',
      ),
    },
  };
}

export function buildCairoTallyInput(rawInput, evaluated) {
  const fields = {
    packed_vals: splitObject(evaluated.publicFields.packedVals, 'packedVals'),
    state_commitment: splitObject(evaluated.publicFields.stateCommitment, 'stateCommitment'),
    current_tally_commitment: splitObject(
      evaluated.publicFields.currentTallyCommitment,
      'currentTallyCommitment',
    ),
    new_tally_commitment: splitObject(evaluated.publicFields.newTallyCommitment, 'newTallyCommitment'),
    input_hash: splitObject(evaluated.publicFields.inputHash, 'inputHash'),
  };

  return {
    fields,
    witness_summary: {
      state_root: splitObject(BigInt(rawInput.stateRoot), 'stateRoot'),
      state_salt: splitObject(BigInt(rawInput.stateSalt), 'stateSalt'),
      new_results_root_salt: splitObject(BigInt(rawInput.newResultsRootSalt), 'newResultsRootSalt'),
    },
    program_input: {
      fields,
      witness: buildCairoProgramWitness(rawInput, evaluated),
    },
    full_witness: rawInput,
    public_output: evaluated.publicOutput.decimalFelts,
  };
}

function pushU256(args, value) {
  args.push(value.low, value.high);
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

function pushSha256U256x4Claim(args, value) {
  pushVector4(args, value.inputs);
  pushU256(args, value.out);
}

function pushTallyPublicFields(args, fields) {
  pushU256(args, fields.packed_vals);
  pushU256(args, fields.state_commitment);
  pushU256(args, fields.current_tally_commitment);
  pushU256(args, fields.new_tally_commitment);
  pushU256(args, fields.input_hash);
}

function pushTallyHashTranscript(args, hashes) {
  pushHash2Claim(args, hashes.state_commitment);
  pushSha256U256x4Claim(args, hashes.input_hash);
  pushHash10Claim(args, hashes.state_leaf_0);
  pushHash10Claim(args, hashes.state_leaf_1);
  pushHash10Claim(args, hashes.state_leaf_2);
  pushHash10Claim(args, hashes.state_leaf_3);
  pushHash10Claim(args, hashes.state_leaf_4);
  pushHash5Claim(args, hashes.state_subroot);
  pushHash5Claim(args, hashes.state_root_from_path);
  pushHash5Claim(args, hashes.vote_zero_root);
  pushHash5Claim(args, hashes.vote_root_0);
  pushHash5Claim(args, hashes.vote_root_1);
  pushHash5Claim(args, hashes.vote_root_2);
  pushHash5Claim(args, hashes.vote_root_3);
  pushHash5Claim(args, hashes.vote_root_4);
  pushHash5Claim(args, hashes.current_results_root);
  pushHash2Claim(args, hashes.current_tally_commitment);
  pushHash5Claim(args, hashes.new_results_root);
  pushHash2Claim(args, hashes.new_tally_commitment);
}

function pushTallyWitness(args, witness) {
  pushU256(args, witness.state_root);
  pushU256(args, witness.state_salt);
  pushU256(args, witness.num_signups);
  pushU256(args, witness.batch_num);
  pushVector10(args, witness.state_leaf_0);
  pushVector10(args, witness.state_leaf_1);
  pushVector10(args, witness.state_leaf_2);
  pushVector10(args, witness.state_leaf_3);
  pushVector10(args, witness.state_leaf_4);
  pushVector4(args, witness.state_path_elements);
  pushVector5(args, witness.votes_0);
  pushVector5(args, witness.votes_1);
  pushVector5(args, witness.votes_2);
  pushVector5(args, witness.votes_3);
  pushVector5(args, witness.votes_4);
  pushVector5(args, witness.current_results);
  pushU256(args, witness.current_results_root_salt);
  pushU256(args, witness.new_results_root_salt);
  pushTallyHashTranscript(args, witness.hashes);
}

export function serializeCairoExecutableArgs(cairoInput) {
  const args = [];
  pushTallyPublicFields(args, cairoInput.program_input.fields);
  pushTallyWitness(args, cairoInput.program_input.witness);
  return args.map((value) => bigintToHex(BigInt(value)));
}
