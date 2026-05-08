import { SMALL_TALLY_PARAMS } from '../constants.mjs';
import { joinU128Pair, parseBigInt } from '../compat/encoding.mjs';
import { canonicalTallyPublicOutput } from '../public-output.mjs';

const BATCH_SIZE = 5n;
const TWO_POW_32 = 1n << 32n;
const MAX_VOTES = 10n ** 24n;

function readU256(value, label) {
  if (!value || typeof value !== 'object') {
    throw new Error(`${label} must be a split u256 object`);
  }
  return joinU128Pair(value.low, value.high, label);
}

function readVector4(value, label) {
  return [
    readU256(value.v0, `${label}.v0`),
    readU256(value.v1, `${label}.v1`),
    readU256(value.v2, `${label}.v2`),
    readU256(value.v3, `${label}.v3`),
  ];
}

function readVector5(value, label) {
  return [
    readU256(value.v0, `${label}.v0`),
    readU256(value.v1, `${label}.v1`),
    readU256(value.v2, `${label}.v2`),
    readU256(value.v3, `${label}.v3`),
    readU256(value.v4, `${label}.v4`),
  ];
}

function readVector10(value, label) {
  return [
    readU256(value.v0, `${label}.v0`),
    readU256(value.v1, `${label}.v1`),
    readU256(value.v2, `${label}.v2`),
    readU256(value.v3, `${label}.v3`),
    readU256(value.v4, `${label}.v4`),
    readU256(value.v5, `${label}.v5`),
    readU256(value.v6, `${label}.v6`),
    readU256(value.v7, `${label}.v7`),
    readU256(value.v8, `${label}.v8`),
    readU256(value.v9, `${label}.v9`),
  ];
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch: expected ${expected.toString()}, got ${actual.toString()}`);
  }
}

function expectVectorEqual(actual, expected, label) {
  for (let i = 0; i < actual.length; i += 1) {
    expectEqual(actual[i], expected[i], `${label}[${i}]`);
  }
}

function poseidonHash2Claim(claim, in0, in1, label) {
  expectEqual(readU256(claim.in0, `${label}.in0`), in0, `${label}.in0`);
  expectEqual(readU256(claim.in1, `${label}.in1`), in1, `${label}.in1`);
  return readU256(claim.out, `${label}.out`);
}

function poseidonHash5Claim(claim, inputs, label) {
  expectVectorEqual(readVector5(claim.inputs, `${label}.inputs`), inputs, `${label}.inputs`);
  return readU256(claim.out, `${label}.out`);
}

function poseidonHash10Claim(claim, inputs, label) {
  const first = poseidonHash5Claim(claim.first, inputs.slice(0, 5), `${label}.first`);
  const second = poseidonHash5Claim(claim.second, inputs.slice(5, 10), `${label}.second`);
  return poseidonHash2Claim(claim.out, first, second, `${label}.out`);
}

function sha256U256x4Claim(claim, inputs, label) {
  expectVectorEqual(readVector4(claim.inputs, `${label}.inputs`), inputs, `${label}.inputs`);
  return readU256(claim.out, `${label}.out`);
}

function selectExpectedVoteRoot(stateLeaf, zeroRoot) {
  return stateLeaf[3] === 0n ? zeroRoot : stateLeaf[3];
}

function statePathInputs(stateSubroot, pathElements, batchNum) {
  const idx = Number(batchNum);
  if (!Number.isInteger(idx) || idx < 0 || idx > 4) {
    throw new Error(`batchNum must be between 0 and 4 for TallyVotes(2,1,1), got ${batchNum}`);
  }

  const inputs = [];
  let pathCursor = 0;
  for (let i = 0; i < 5; i += 1) {
    if (i === idx) {
      inputs.push(stateSubroot);
    } else {
      inputs.push(pathElements[pathCursor]);
      pathCursor += 1;
    }
  }
  return inputs;
}

function tallyVote(vote) {
  return vote * (vote + MAX_VOTES);
}

function tallyOption(currentResult, isFirstBatch, votes) {
  const base = isFirstBatch ? 0n : currentResult;
  return votes.reduce((sum, vote) => sum + tallyVote(vote), base);
}

function computeNewResults(currentResults, isFirstBatch, votesByVoter) {
  const results = [];
  for (let option = 0; option < 5; option += 1) {
    results.push(
      tallyOption(
        currentResults[option],
        isFirstBatch,
        votesByVoter.map((votes) => votes[option]),
      ),
    );
  }
  return results;
}

export function runTallyCairoModel(programInput) {
  const fields = {
    packedVals: readU256(programInput.fields.packed_vals, 'fields.packed_vals'),
    stateCommitment: readU256(programInput.fields.state_commitment, 'fields.state_commitment'),
    currentTallyCommitment: readU256(
      programInput.fields.current_tally_commitment,
      'fields.current_tally_commitment',
    ),
    newTallyCommitment: readU256(programInput.fields.new_tally_commitment, 'fields.new_tally_commitment'),
    inputHash: readU256(programInput.fields.input_hash, 'fields.input_hash'),
  };

  const witness = programInput.witness;
  const hashes = witness.hashes;
  const stateRoot = readU256(witness.state_root, 'witness.state_root');
  const stateSalt = readU256(witness.state_salt, 'witness.state_salt');
  const numSignUps = readU256(witness.num_signups, 'witness.num_signups');
  const batchNum = readU256(witness.batch_num, 'witness.batch_num');
  if (batchNum > 4n) {
    throw new Error('BATCH_RANGE');
  }

  expectEqual(numSignUps * TWO_POW_32 + batchNum, fields.packedVals, 'packedVals');
  const batchStartIndex = batchNum * BATCH_SIZE;
  if (batchStartIndex > numSignUps) {
    throw new Error('BAD_NUM_SIGNUPS');
  }
  const isFirstBatch = batchStartIndex === 0n;

  const stateCommitment = poseidonHash2Claim(hashes.state_commitment, stateRoot, stateSalt, 'stateCommitment');
  expectEqual(stateCommitment, fields.stateCommitment, 'stateCommitment');

  const inputHash = sha256U256x4Claim(
    hashes.input_hash,
    [
      fields.packedVals,
      fields.stateCommitment,
      fields.currentTallyCommitment,
      fields.newTallyCommitment,
    ],
    'inputHash',
  );
  expectEqual(inputHash, fields.inputHash, 'inputHash');

  const stateLeaves = [
    readVector10(witness.state_leaf_0, 'witness.state_leaf_0'),
    readVector10(witness.state_leaf_1, 'witness.state_leaf_1'),
    readVector10(witness.state_leaf_2, 'witness.state_leaf_2'),
    readVector10(witness.state_leaf_3, 'witness.state_leaf_3'),
    readVector10(witness.state_leaf_4, 'witness.state_leaf_4'),
  ];
  const stateLeafHashes = [
    poseidonHash10Claim(hashes.state_leaf_0, stateLeaves[0], 'stateLeaf0'),
    poseidonHash10Claim(hashes.state_leaf_1, stateLeaves[1], 'stateLeaf1'),
    poseidonHash10Claim(hashes.state_leaf_2, stateLeaves[2], 'stateLeaf2'),
    poseidonHash10Claim(hashes.state_leaf_3, stateLeaves[3], 'stateLeaf3'),
    poseidonHash10Claim(hashes.state_leaf_4, stateLeaves[4], 'stateLeaf4'),
  ];
  const stateSubroot = poseidonHash5Claim(hashes.state_subroot, stateLeafHashes, 'stateSubroot');
  const pathElements = readVector4(witness.state_path_elements, 'witness.state_path_elements');
  const stateRootFromPath = poseidonHash5Claim(
    hashes.state_root_from_path,
    statePathInputs(stateSubroot, pathElements, batchNum),
    'stateRootFromPath',
  );
  expectEqual(stateRootFromPath, stateRoot, 'stateRootFromPath');

  const zeroRoot = poseidonHash5Claim(hashes.vote_zero_root, [0n, 0n, 0n, 0n, 0n], 'voteZeroRoot');
  const votesByVoter = [
    readVector5(witness.votes_0, 'witness.votes_0'),
    readVector5(witness.votes_1, 'witness.votes_1'),
    readVector5(witness.votes_2, 'witness.votes_2'),
    readVector5(witness.votes_3, 'witness.votes_3'),
    readVector5(witness.votes_4, 'witness.votes_4'),
  ];
  const voteRoots = [
    poseidonHash5Claim(hashes.vote_root_0, votesByVoter[0], 'voteRoot0'),
    poseidonHash5Claim(hashes.vote_root_1, votesByVoter[1], 'voteRoot1'),
    poseidonHash5Claim(hashes.vote_root_2, votesByVoter[2], 'voteRoot2'),
    poseidonHash5Claim(hashes.vote_root_3, votesByVoter[3], 'voteRoot3'),
    poseidonHash5Claim(hashes.vote_root_4, votesByVoter[4], 'voteRoot4'),
  ];
  for (let i = 0; i < 5; i += 1) {
    expectEqual(voteRoots[i], selectExpectedVoteRoot(stateLeaves[i], zeroRoot), `voteRoot[${i}]`);
  }

  const currentResults = readVector5(witness.current_results, 'witness.current_results');
  const currentResultsRoot = poseidonHash5Claim(hashes.current_results_root, currentResults, 'currentResultsRoot');
  const currentResultsRootSalt = readU256(
    witness.current_results_root_salt,
    'witness.current_results_root_salt',
  );
  const currentTallyCommitment = poseidonHash2Claim(
    hashes.current_tally_commitment,
    currentResultsRoot,
    currentResultsRootSalt,
    'currentTallyCommitment',
  );
  expectEqual(
    isFirstBatch ? 0n : currentTallyCommitment,
    fields.currentTallyCommitment,
    'currentTallyCommitment',
  );

  const newResults = computeNewResults(currentResults, isFirstBatch, votesByVoter);
  const newResultsRoot = poseidonHash5Claim(hashes.new_results_root, newResults, 'newResultsRoot');
  const newResultsRootSalt = readU256(witness.new_results_root_salt, 'witness.new_results_root_salt');
  const newTallyCommitment = poseidonHash2Claim(
    hashes.new_tally_commitment,
    newResultsRoot,
    newResultsRootSalt,
    'newTallyCommitment',
  );
  expectEqual(newTallyCommitment, fields.newTallyCommitment, 'newTallyCommitment');

  return {
    publicFields: fields,
    publicOutput: canonicalTallyPublicOutput(fields, SMALL_TALLY_PARAMS),
    derived: {
      numSignUps,
      batchNum,
      batchStartIndex,
      stateSubroot,
      newResults,
      newResultsRoot,
    },
  };
}

export function mutateSplitU256(split, delta = 1n) {
  const value = readU256(split, 'mutated');
  const mutated = value + parseBigInt(delta, 'delta');
  return {
    low: (mutated & ((1n << 128n) - 1n)).toString(),
    high: (mutated >> 128n).toString(),
  };
}
