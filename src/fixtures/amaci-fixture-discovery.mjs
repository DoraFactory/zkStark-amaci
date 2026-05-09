import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { evaluateTallyVotes } from '../tally/tally-votes.mjs';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function walkJsonFiles(root) {
  const out = [];
  const stack = [resolve(root)];
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry);
      const stat = statSync(path);
      if (stat.isDirectory()) {
        stack.push(path);
      } else if (entry.endsWith('.json')) {
        out.push(path);
      }
    }
  }
  return out.sort();
}

function arrayLength(value) {
  return Array.isArray(value) ? value.length : undefined;
}

function nestedLength(value) {
  return Array.isArray(value) && Array.isArray(value[0]) ? value[0].length : undefined;
}

function classifyTally(input) {
  const shape = {
    stateLeafCount: arrayLength(input.stateLeaf),
    stateLeafWidth: nestedLength(input.stateLeaf),
    votesRows: arrayLength(input.votes),
    votesCols: nestedLength(input.votes),
    currentResultsCount: arrayLength(input.currentResults),
    statePathDepth: arrayLength(input.statePathElements),
  };
  const supported =
    shape.stateLeafCount === 5 &&
    shape.stateLeafWidth === 10 &&
    shape.votesRows === 5 &&
    shape.votesCols === 5 &&
    shape.currentResultsCount === 5 &&
    shape.statePathDepth === 1;
  return {
    circuit: 'tally',
    supported,
    supportedProgram: supported ? 'tally_votes' : undefined,
    shape,
    unsupportedReason: supported
      ? undefined
      : 'current Cairo target only supports TallyVotes(2,1,1): 5 state leaves, 5 vote options, depth-1 batch path',
  };
}

function classifyProcessMessages(input) {
  const shape = {
    messageCount: arrayLength(input.msgs),
    messageWidth: nestedLength(input.msgs),
    encPubKeyCount: arrayLength(input.encPubKeys),
    stateLeafCount: arrayLength(input.currentStateLeaves),
    statePathDepth: Array.isArray(input.currentStateLeavesPathElements?.[0])
      ? input.currentStateLeavesPathElements[0].length
      : undefined,
    votePathDepth: Array.isArray(input.currentVoteWeightsPathElements?.[0])
      ? input.currentVoteWeightsPathElements[0].length
      : undefined,
  };
  const supported =
    shape.messageCount === 5 &&
    shape.messageWidth === 10 &&
    shape.encPubKeyCount === 5 &&
    shape.stateLeafCount === 5 &&
    shape.statePathDepth === 2 &&
    shape.votePathDepth === 1 &&
    Array.isArray(input.processOneWitnesses) &&
    input.processOneWitnesses.length === 5;
  return {
    circuit: 'process-messages',
    supported,
    supportedProgram: supported ? 'process_messages_stateful_with_ecdh_signature' : undefined,
    shape,
    unsupportedReason: supported
      ? undefined
      : 'current Cairo target only supports ProcessMessages(2,1,5) with prepared ProcessOne witnesses',
  };
}

function classifyProcessDeactivate(input) {
  const shape = {
    messageCount: arrayLength(input.msgs),
    messageWidth: nestedLength(input.msgs),
    encPubKeyCount: arrayLength(input.encPubKeys),
    processOneCount: arrayLength(input.processOneWitnesses),
  };
  const supported =
    shape.messageCount === 5 &&
    shape.messageWidth === 10 &&
    shape.encPubKeyCount === 5 &&
    shape.processOneCount === 5 &&
    input.newDeactivateRoot !== undefined;
  return {
    circuit: 'process-deactivate',
    supported,
    supportedProgram: supported ? 'process_deactivate_messages_stateful' : undefined,
    shape,
    unsupportedReason: supported
      ? undefined
      : 'current Cairo target only supports ProcessDeactivateMessages(2,5) with prepared ProcessOne witnesses',
  };
}

function classifyAddNewKey(input) {
  const shape = {
    deactivatePathDepth: arrayLength(input.deactivateLeafPathElements),
    coordPubKeyWidth: arrayLength(input.coordPubKey),
    c1Width: arrayLength(input.c1),
    c2Width: arrayLength(input.c2),
  };
  const supported =
    shape.deactivatePathDepth === 4 &&
    shape.coordPubKeyWidth === 2 &&
    shape.c1Width === 2 &&
    shape.c2Width === 2;
  return {
    circuit: 'add-new-key',
    supported,
    supportedProgram: supported ? 'add_new_key' : undefined,
    shape,
    unsupportedReason: supported
      ? undefined
      : 'current Cairo target only supports AddNewKey(stateTreeDepth=2), deactivate tree depth 4',
  };
}

export function classifyAmaciFixture(input) {
  if (!isObject(input)) {
    return { circuit: 'unknown', supported: false, unsupportedReason: 'not a JSON object' };
  }
  if (input.votes !== undefined && input.currentResults !== undefined) {
    return classifyTally(input);
  }
  if (input.d1 !== undefined && input.d2 !== undefined && input.newPubKey !== undefined) {
    return classifyAddNewKey(input);
  }
  if (input.newDeactivateCommitment !== undefined && input.currentDeactivateCommitment !== undefined) {
    return classifyProcessDeactivate(input);
  }
  if (input.msgs !== undefined && input.currentStateCommitment !== undefined) {
    return classifyProcessMessages(input);
  }
  return {
    circuit: 'unknown',
    supported: false,
    unsupportedReason: 'does not match a known AMACI circuit input shape',
  };
}

function maybeValidateTally(input, classification) {
  if (classification.circuit !== 'tally' || !classification.supported) {
    return undefined;
  }
  const evaluated = evaluateTallyVotes(input);
  return {
    inputHash: evaluated.publicFields.inputHash.toString(),
    newTallyCommitment: evaluated.publicFields.newTallyCommitment.toString(),
    publicOutputFelts: evaluated.publicOutput.decimalFelts.length,
  };
}

export function discoverAmaciFixtures(root, { validate = false } = {}) {
  const rootPath = resolve(root);
  const fixtures = [];
  const counts = {};

  for (const path of walkJsonFiles(rootPath)) {
    let classification;
    let validation;
    try {
      const input = readJson(path);
      classification = classifyAmaciFixture(input);
      if (validate) {
        validation = maybeValidateTally(input, classification);
      }
    } catch (error) {
      classification = {
        circuit: 'invalid-json',
        supported: false,
        unsupportedReason: error.message,
      };
    }
    counts[classification.circuit] = (counts[classification.circuit] ?? 0) + 1;
    fixtures.push({
      path,
      relativePath: relative(rootPath, path),
      ...classification,
      ...(validation === undefined ? {} : { validation }),
    });
  }

  return {
    root: rootPath,
    counts,
    supportedCount: fixtures.filter((fixture) => fixture.supported).length,
    fixtures,
  };
}
