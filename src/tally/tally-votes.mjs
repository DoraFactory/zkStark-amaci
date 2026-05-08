import { MAX_VOTES, SMALL_TALLY_PARAMS, TREE_ARITY } from '../constants.mjs';
import { deepMapBigInt, parseBigInt, tallyInputHash } from '../compat/encoding.mjs';
import { hash5, hash10, hashLeftRight } from '../compat/poseidon.mjs';
import { quinaryInclusionRoot, quinaryRoot, zeroRoot } from '../compat/quinary-tree.mjs';
import { canonicalTallyPublicOutput } from '../public-output.mjs';

function assertSupportedParams(params) {
  if (
    params.stateTreeDepth !== 2 ||
    params.intStateTreeDepth !== 1 ||
    params.voteOptionTreeDepth !== 1
  ) {
    throw new Error('only AMACI TallyVotes(2, 1, 1) is supported in the first zkStark-amaci prototype');
  }
}

export function unpackPackedVals(packedVals) {
  const packed = parseBigInt(packedVals, 'packedVals');
  const mask32 = (1n << 32n) - 1n;
  return {
    numSignUps: packed >> 32n,
    batchNum: packed & mask32,
  };
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch: expected ${expected.toString()}, got ${actual.toString()}`);
  }
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

export function evaluateTallyVotes(rawInput, params = SMALL_TALLY_PARAMS) {
  assertSupportedParams(params);

  const batchSize = TREE_ARITY ** params.intStateTreeDepth;
  const numVoteOptions = TREE_ARITY ** params.voteOptionTreeDepth;
  const pathDepth = params.stateTreeDepth - params.intStateTreeDepth;

  const input = {
    stateRoot: parseBigInt(rawInput.stateRoot, 'stateRoot'),
    stateSalt: parseBigInt(rawInput.stateSalt, 'stateSalt'),
    packedVals: parseBigInt(rawInput.packedVals, 'packedVals'),
    stateCommitment: parseBigInt(rawInput.stateCommitment, 'stateCommitment'),
    currentTallyCommitment: parseBigInt(rawInput.currentTallyCommitment, 'currentTallyCommitment'),
    newTallyCommitment: parseBigInt(rawInput.newTallyCommitment, 'newTallyCommitment'),
    inputHash: parseBigInt(rawInput.inputHash, 'inputHash'),
    stateLeaf: deepMapBigInt(rawInput.stateLeaf),
    statePathElements: deepMapBigInt(rawInput.statePathElements),
    votes: deepMapBigInt(rawInput.votes),
    currentResults: deepMapBigInt(rawInput.currentResults),
    currentResultsRootSalt: parseBigInt(rawInput.currentResultsRootSalt, 'currentResultsRootSalt'),
    newResultsRootSalt: parseBigInt(rawInput.newResultsRootSalt, 'newResultsRootSalt'),
  };

  expectMatrixShape(input.stateLeaf, batchSize, 10, 'stateLeaf');
  expectMatrixShape(input.votes, batchSize, numVoteOptions, 'votes');
  expectMatrixShape(input.statePathElements, pathDepth, TREE_ARITY - 1, 'statePathElements');
  if (!Array.isArray(input.currentResults) || input.currentResults.length !== numVoteOptions) {
    throw new Error(`currentResults must contain ${numVoteOptions} values`);
  }

  expectEqual(hashLeftRight(input.stateRoot, input.stateSalt), input.stateCommitment, 'stateCommitment');

  const expectedInputHash = tallyInputHash(
    input.packedVals,
    input.stateCommitment,
    input.currentTallyCommitment,
    input.newTallyCommitment,
  );
  expectEqual(expectedInputHash, input.inputHash, 'inputHash');

  const { numSignUps, batchNum } = unpackPackedVals(input.packedVals);
  const batchStartIndex = batchNum * BigInt(batchSize);
  if (batchStartIndex > numSignUps) {
    throw new Error('batchStartIndex must be less than or equal to numSignUps');
  }

  const stateLeafHashes = input.stateLeaf.map((leaf) => hash10(leaf));
  const stateSubroot = quinaryRoot(stateLeafHashes, params.intStateTreeDepth);
  const derivedStateRoot = quinaryInclusionRoot(stateSubroot, input.statePathElements, batchNum);
  expectEqual(derivedStateRoot, input.stateRoot, 'stateRoot inclusion');

  const voteZeroRoot = zeroRoot(params.voteOptionTreeDepth);
  const voteRoots = [];
  for (let i = 0; i < batchSize; i += 1) {
    const root = quinaryRoot(input.votes[i], params.voteOptionTreeDepth);
    voteRoots.push(root);
    const expectedRoot = input.stateLeaf[i][3] === 0n ? voteZeroRoot : input.stateLeaf[i][3];
    expectEqual(root, expectedRoot, `vote option root for stateLeaf[${i}]`);
  }

  const isFirstBatch = batchStartIndex === 0n;
  const currentResultsRoot = quinaryRoot(input.currentResults, params.voteOptionTreeDepth);
  const currentResultsCommitment = hashLeftRight(currentResultsRoot, input.currentResultsRootSalt);
  expectEqual(
    isFirstBatch ? 0n : currentResultsCommitment,
    input.currentTallyCommitment,
    'currentTallyCommitment',
  );

  const newResults = [];
  for (let option = 0; option < numVoteOptions; option += 1) {
    let sum = isFirstBatch ? 0n : input.currentResults[option];
    for (let voter = 0; voter < batchSize; voter += 1) {
      const vote = input.votes[voter][option];
      sum += vote * (vote + MAX_VOTES);
    }
    newResults.push(sum);
  }

  const newResultsRoot = quinaryRoot(newResults, params.voteOptionTreeDepth);
  const derivedNewTallyCommitment = hashLeftRight(newResultsRoot, input.newResultsRootSalt);
  expectEqual(derivedNewTallyCommitment, input.newTallyCommitment, 'newTallyCommitment');

  const publicFields = {
    packedVals: input.packedVals,
    stateCommitment: input.stateCommitment,
    currentTallyCommitment: input.currentTallyCommitment,
    newTallyCommitment: input.newTallyCommitment,
    inputHash: input.inputHash,
  };

  return {
    params,
    publicFields,
    publicOutput: canonicalTallyPublicOutput(publicFields, params),
    derived: {
      numSignUps,
      batchNum,
      batchStartIndex,
      stateSubroot,
      stateLeafHashes,
      voteRoots,
      voteZeroRoot,
      currentResultsRoot,
      currentResultsCommitment,
      newResults,
      newResultsRoot,
      newTallyCommitment: derivedNewTallyCommitment,
      inputHash: expectedInputHash,
    },
  };
}
