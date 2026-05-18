import {
  MAX_VOTES,
  NATIVE_PUBLIC_OUTPUT_VERSION,
  PUBLIC_OUTPUT_MAGIC,
  SMALL_TALLY_PARAMS,
  STARK_FIELD,
  STARKNET_POSEIDON_HASH_SCHEME,
  TALLY_NATIVE_INPUT_HASH_DOMAIN,
  TALLY_VOTES_NATIVE_CIRCUIT_ID,
  TREE_ARITY,
} from '../constants.mjs';
import { decimalize, parseBigInt } from '../compat/encoding.mjs';
import { poseidonManyFelts } from '../integrity/hashes.mjs';
import { unpackPackedVals } from './tally-votes.mjs';

const U32_MAX = (1n << 32n) - 1n;

function assertSupportedParams(params) {
  if (
    params.stateTreeDepth !== 2 ||
    params.intStateTreeDepth !== 1 ||
    params.voteOptionTreeDepth !== 1
  ) {
    throw new Error('only AMACI-STARK v2 TallyVotesNative(2, 1, 1) is supported');
  }
}

export function toStarkFelt(value, label = 'value') {
  const parsed = parseBigInt(value, label);
  const reduced = parsed % STARK_FIELD;
  return reduced >= 0n ? reduced : reduced + STARK_FIELD;
}

function feltVector(values, expected, label) {
  if (!Array.isArray(values) || values.length !== expected) {
    throw new Error(`${label} must contain ${expected} values`);
  }
  return values.map((value, index) => toStarkFelt(value, `${label}[${index}]`));
}

function expectMatrixShape(matrix, rows, cols, label) {
  if (!Array.isArray(matrix) || matrix.length !== rows) {
    throw new Error(`${label} must contain ${rows} rows`);
  }
  for (let i = 0; i < rows; i += 1) {
    if (!Array.isArray(matrix[i]) || matrix[i].length !== cols) {
      throw new Error(`${label}[${i}] must contain ${cols} values`);
    }
  }
}

function hashMany(values) {
  return poseidonManyFelts(values.map((value, index) => toStarkFelt(value, `hash[${index}]`)));
}

function hash2(left, right) {
  return hashMany([left, right]);
}

function hash5(values) {
  return hashMany(feltVector(values, 5, 'hash5'));
}

function hash10(values) {
  const normalized = feltVector(values, 10, 'hash10');
  return hash2(hash5(normalized.slice(0, 5)), hash5(normalized.slice(5, 10)));
}

function statePathInputs(stateSubroot, statePathElements, batchNum) {
  const inputs = [];
  let pathCursor = 0;
  for (let i = 0; i < TREE_ARITY; i += 1) {
    if (BigInt(i) === batchNum) {
      inputs.push(stateSubroot);
    } else {
      inputs.push(statePathElements[pathCursor]);
      pathCursor += 1;
    }
  }
  return inputs;
}

function tallyVote(vote) {
  return toStarkFelt(vote * (vote + MAX_VOTES), 'tallyVote');
}

function canonicalNativeTallyPublicOutput(fields, params) {
  const labels = [
    'magic',
    'version',
    'circuit_id',
    'hash_scheme',
    'state_tree_depth',
    'int_state_tree_depth',
    'vote_option_tree_depth',
    'packed_vals',
    'state_commitment',
    'current_tally_commitment',
    'new_tally_commitment',
    'input_hash',
  ];
  const felts = [
    PUBLIC_OUTPUT_MAGIC,
    NATIVE_PUBLIC_OUTPUT_VERSION,
    TALLY_VOTES_NATIVE_CIRCUIT_ID,
    STARKNET_POSEIDON_HASH_SCHEME,
    BigInt(params.stateTreeDepth),
    BigInt(params.intStateTreeDepth),
    BigInt(params.voteOptionTreeDepth),
    fields.packedVals,
    fields.stateCommitment,
    fields.currentTallyCommitment,
    fields.newTallyCommitment,
    fields.inputHash,
  ];
  return {
    labels,
    felts,
    decimalFelts: felts.map(decimalize),
  };
}

export function evaluateNativeTallyVotes(rawInput, params = SMALL_TALLY_PARAMS) {
  assertSupportedParams(params);

  const batchSize = TREE_ARITY ** params.intStateTreeDepth;
  const numVoteOptions = TREE_ARITY ** params.voteOptionTreeDepth;
  const pathDepth = params.stateTreeDepth - params.intStateTreeDepth;

  expectMatrixShape(rawInput.stateLeaf, batchSize, 10, 'stateLeaf');
  expectMatrixShape(rawInput.votes, batchSize, numVoteOptions, 'votes');
  expectMatrixShape(rawInput.statePathElements, pathDepth, TREE_ARITY - 1, 'statePathElements');
  if (!Array.isArray(rawInput.currentResults) || rawInput.currentResults.length !== numVoteOptions) {
    throw new Error(`currentResults must contain ${numVoteOptions} values`);
  }

  const { numSignUps, batchNum } = unpackPackedVals(rawInput.packedVals);
  if (numSignUps > U32_MAX) {
    throw new Error('numSignUps must fit in u32');
  }
  if (batchNum < 0n || batchNum >= BigInt(TREE_ARITY)) {
    throw new Error(`batchNum must be in [0, ${TREE_ARITY - 1}]`);
  }
  const batchStartIndex = batchNum * BigInt(batchSize);
  if (batchStartIndex > numSignUps) {
    throw new Error('batchStartIndex must be less than or equal to numSignUps');
  }

  const stateSalt = toStarkFelt(rawInput.stateSalt, 'stateSalt');
  const currentResultsRootSalt = toStarkFelt(
    rawInput.currentResultsRootSalt,
    'currentResultsRootSalt',
  );
  const newResultsRootSalt = toStarkFelt(rawInput.newResultsRootSalt, 'newResultsRootSalt');
  const votes = rawInput.votes.map((row, index) => feltVector(row, numVoteOptions, `votes[${index}]`));
  const currentResults = feltVector(rawInput.currentResults, numVoteOptions, 'currentResults');
  const statePathElements = feltVector(rawInput.statePathElements[0], TREE_ARITY - 1, 'statePathElements[0]');

  const voteZeroRoot = hash5([0n, 0n, 0n, 0n, 0n]);
  const voteRoots = votes.map((row) => hash5(row));
  const stateLeaves = rawInput.stateLeaf.map((leaf, index) => {
    const normalized = feltVector(leaf, 10, `stateLeaf[${index}]`);
    const originalVoteRoot = parseBigInt(leaf[3], `stateLeaf[${index}][3]`);
    return [
      normalized[0],
      normalized[1],
      normalized[2],
      originalVoteRoot === 0n ? 0n : voteRoots[index],
      normalized[4],
      normalized[5],
      normalized[6],
      normalized[7],
      normalized[8],
      normalized[9],
    ];
  });
  const stateLeafHashes = stateLeaves.map(hash10);
  const stateSubroot = hash5(stateLeafHashes);
  const stateRoot = hash5(statePathInputs(stateSubroot, statePathElements, batchNum));
  const stateCommitment = hash2(stateRoot, stateSalt);
  const isFirstBatch = batchStartIndex === 0n;
  const currentResultsRoot = hash5(currentResults);
  const currentResultsCommitment = hash2(currentResultsRoot, currentResultsRootSalt);
  const currentTallyCommitment = isFirstBatch ? 0n : currentResultsCommitment;

  const newResults = [];
  for (let option = 0; option < numVoteOptions; option += 1) {
    let sum = isFirstBatch ? 0n : currentResults[option];
    for (let voter = 0; voter < batchSize; voter += 1) {
      sum += tallyVote(votes[voter][option]);
    }
    newResults.push(toStarkFelt(sum, `newResults[${option}]`));
  }
  const newResultsRoot = hash5(newResults);
  const newTallyCommitment = hash2(newResultsRoot, newResultsRootSalt);
  const packedVals = toStarkFelt(numSignUps * (1n << 32n) + batchNum, 'packedVals');
  const inputHash = hashMany([
    TALLY_NATIVE_INPUT_HASH_DOMAIN,
    packedVals,
    stateCommitment,
    currentTallyCommitment,
    newTallyCommitment,
  ]);

  const publicFields = {
    packedVals,
    stateCommitment,
    currentTallyCommitment,
    newTallyCommitment,
    inputHash,
  };

  return {
    params,
    publicFields,
    publicOutput: canonicalNativeTallyPublicOutput(publicFields, params),
    nativeWitness: {
      stateRoot,
      stateSalt,
      numSignUps: toStarkFelt(numSignUps, 'numSignUps'),
      batchNum: toStarkFelt(batchNum, 'batchNum'),
      stateLeaves,
      statePathElements,
      votes,
      currentResults,
      currentResultsRootSalt,
      newResultsRootSalt,
    },
    derived: {
      numSignUps,
      batchNum,
      batchStartIndex,
      stateSubroot,
      stateLeafHashes,
      stateRoot,
      voteRoots,
      voteZeroRoot,
      currentResultsRoot,
      currentResultsCommitment,
      newResults,
      newResultsRoot,
      newTallyCommitment,
      inputHash,
    },
  };
}
