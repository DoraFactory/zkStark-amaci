import { TREE_ARITY } from '../constants.mjs';
import { parseBigInt } from '../compat/encoding.mjs';
import { poseidonManyFelts } from '../integrity/hashes.mjs';
import { toStarkFelt } from '../tally/native-tally-votes.mjs';

function nativeHashFelts(values, label) {
  return poseidonManyFelts(values.map((value, index) => toStarkFelt(value, `${label}[${index}]`)));
}

export function nativeHash5(values, label = 'hash5') {
  if (!Array.isArray(values) || values.length !== 5) {
    throw new Error(`${label} must contain five values`);
  }
  return nativeHashFelts(values, label);
}

export function nativeHash10(values, label = 'hash10') {
  if (!Array.isArray(values) || values.length !== 10) {
    throw new Error(`${label} must contain ten values`);
  }
  return nativeHashFelts([
    nativeHash5(values.slice(0, 5), `${label}.first`),
    nativeHash5(values.slice(5, 10), `${label}.second`),
  ], `${label}.out`);
}

export function nativeQuinaryInclusionRoot(leaf, pathElements, index, label = 'path') {
  if (!Array.isArray(pathElements)) {
    throw new Error(`${label} pathElements must be an array`);
  }

  let cursor = parseBigInt(index, `${label}.index`);
  let node = toStarkFelt(leaf, `${label}.leaf`);
  for (let level = 0; level < pathElements.length; level += 1) {
    const siblings = pathElements[level];
    if (!Array.isArray(siblings) || siblings.length !== TREE_ARITY - 1) {
      throw new Error(`${label}.pathElements[${level}] must contain ${TREE_ARITY - 1} siblings`);
    }
    const pathIndex = Number(cursor % BigInt(TREE_ARITY));
    const children = [];
    let siblingIndex = 0;
    for (let indexInLevel = 0; indexInLevel < TREE_ARITY; indexInLevel += 1) {
      if (indexInLevel === pathIndex) {
        children.push(node);
      } else {
        children.push(siblings[siblingIndex]);
        siblingIndex += 1;
      }
    }
    node = nativeHash5(children, `${label}.level${level}`);
    cursor /= BigInt(TREE_ARITY);
  }
  if (cursor !== 0n) {
    throw new Error(`${label}.index does not fit in ${pathElements.length} quinary levels`);
  }
  return node;
}

function select(isValid, ifInvalid, ifValid) {
  return isValid === 1n ? ifValid : ifInvalid;
}

function nativeCurrentStateLeaf(input, nativeCurrentVoteRoot) {
  const stateLeaf = input.stateLeaf.map((value, index) => toStarkFelt(value, `stateLeaf[${index}]`));
  stateLeaf[3] = input.stateLeaf[3] === 0n ? 0n : nativeCurrentVoteRoot;
  return stateLeaf;
}

function nativeNewStateLeaf(input, derived, nativeCurrentLeafVoteRoot, nativeNewVoteOptionRoot) {
  const { isValid } = derived;
  return [
    select(isValid, input.stateLeaf[0], input.cmdNewPubKey[0]),
    select(isValid, input.stateLeaf[1], input.cmdNewPubKey[1]),
    select(isValid, input.stateLeaf[2], derived.newBalance),
    select(isValid, nativeCurrentLeafVoteRoot, nativeNewVoteOptionRoot),
    select(isValid, input.stateLeaf[4], derived.newSlNonce),
    input.stateLeaf[5],
    input.stateLeaf[6],
    input.stateLeaf[7],
    input.stateLeaf[8],
    0n,
  ].map((value, index) => toStarkFelt(value, `newStateLeaf[${index}]`));
}

export function nativeProcessMessageTransitionRoots(transition) {
  const { input, derived } = transition;
  const stateIndex = derived.stateIndex;
  const voteOptionIndex = derived.voteOptionIndex;
  const currentVoteRoot = nativeQuinaryInclusionRoot(
    input.currentVoteWeight,
    input.currentVoteWeightsPathElements,
    voteOptionIndex,
    'currentVoteRoot',
  );
  const currentStateLeaf = nativeCurrentStateLeaf(input, currentVoteRoot);
  const newVoteOptionRoot = nativeQuinaryInclusionRoot(
    derived.updatedVoteWeight,
    input.currentVoteWeightsPathElements,
    voteOptionIndex,
    'newVoteOptionRoot',
  );
  const newStateLeaf = nativeNewStateLeaf(
    input,
    derived,
    currentStateLeaf[3],
    newVoteOptionRoot,
  );

  return {
    currentVoteRoot,
    newVoteOptionRoot,
    currentStateLeaf,
    newStateLeaf,
    currentStateLeafHash: nativeHash10(currentStateLeaf, 'currentStateLeaf'),
    newStateLeafHash: nativeHash10(newStateLeaf, 'newStateLeaf'),
    currentStateRoot: nativeQuinaryInclusionRoot(
      nativeHash10(currentStateLeaf, 'currentStateLeafRoot'),
      input.stateLeafPathElements,
      stateIndex,
      'currentStateRoot',
    ),
    newStateRoot: nativeQuinaryInclusionRoot(
      nativeHash10(newStateLeaf, 'newStateLeafRoot'),
      input.stateLeafPathElements,
      stateIndex,
      'newStateRoot',
    ),
    activeStateRoot: nativeQuinaryInclusionRoot(
      input.activeStateLeaf,
      input.activeStateLeafPathElements,
      stateIndex,
      'activeStateRoot',
    ),
  };
}

export function nativeProcessMessagesStateRoots(stateResult) {
  const transitionRoots = nativeProcessMessageTransitionContexts(stateResult);
  return {
    transitionRoots,
    currentStateRoot: transitionRoots.at(-1).currentStateRoot,
    newStateRoot: transitionRoots[0].newStateRoot,
    activeStateRoot: toStarkFelt(stateResult.derived.activeStateRoot, 'activeStateRoot'),
  };
}

function splitIndex(index) {
  const cursor = parseBigInt(index, 'index');
  return {
    level0: Number(cursor % BigInt(TREE_ARITY)),
    level1: Number((cursor / BigInt(TREE_ARITY)) % BigInt(TREE_ARITY)),
  };
}

function mapKey(level, index) {
  return `${level}:${index}`;
}

function fallbackPathValue(pathElements, level, siblingCursor, label) {
  return toStarkFelt(pathElements[level][siblingCursor], `${label}.fallback[${level}][${siblingCursor}]`);
}

function statePathFromMaps(nodeMap, leafHash, pathElements, stateIndex, label) {
  const { level0, level1 } = splitIndex(stateIndex);
  const level0Start = level1 * TREE_ARITY;
  const level0Children = [];
  const path0 = [];
  let path0Cursor = 0;
  for (let offset = 0; offset < TREE_ARITY; offset += 1) {
    const absoluteIndex = level0Start + offset;
    if (offset === level0) {
      level0Children.push(leafHash);
    } else {
      const value = nodeMap.get(mapKey(0, absoluteIndex))
        ?? fallbackPathValue(pathElements, 0, path0Cursor, label);
      level0Children.push(value);
      path0.push(value);
      path0Cursor += 1;
    }
  }
  const level1Node = nativeHash5(level0Children, `${label}.level0`);

  const level1Children = [];
  const path1 = [];
  let path1Cursor = 0;
  for (let group = 0; group < TREE_ARITY; group += 1) {
    if (group === level1) {
      level1Children.push(level1Node);
    } else {
      const value = nodeMap.get(mapKey(1, group))
        ?? fallbackPathValue(pathElements, 1, path1Cursor, label);
      level1Children.push(value);
      path1.push(value);
      path1Cursor += 1;
    }
  }

  return {
    path: [path0, path1],
    level0Children,
    level1Children,
    level1Node,
    root: nativeHash5(level1Children, `${label}.root`),
  };
}

function updateStateMaps(nodeMap, stateIndex, level0Children, level1Children, leafHash) {
  const { level0, level1 } = splitIndex(stateIndex);
  const level0Start = level1 * TREE_ARITY;
  nodeMap.set(mapKey(0, level0Start + level0), leafHash);
  nodeMap.set(mapKey(1, level1), nativeHash5(level0Children, `stateMap.group${level1}`));
  nodeMap.set(mapKey(2, 0), nativeHash5(level1Children, 'stateMap.root'));
}

function votePathFromMap(voteNodeMaps, stateIndex, leaf, pathElements, voteOptionIndex, label) {
  const index = Number(parseBigInt(voteOptionIndex, `${label}.voteOptionIndex`));
  const key = parseBigInt(stateIndex, `${label}.stateIndex`).toString();
  let voteMap = voteNodeMaps.get(key);
  if (!voteMap) {
    voteMap = new Map();
    voteNodeMaps.set(key, voteMap);
  }

  const children = [];
  const path = [];
  let pathCursor = 0;
  for (let offset = 0; offset < TREE_ARITY; offset += 1) {
    if (offset === index) {
      children.push(toStarkFelt(leaf, `${label}.leaf`));
    } else {
      const value = voteMap.get(offset)
        ?? toStarkFelt(pathElements[0][pathCursor], `${label}.fallback[${pathCursor}]`);
      children.push(value);
      path.push(value);
      pathCursor += 1;
    }
  }

  return {
    path: [path],
    children,
    root: nativeHash5(children, `${label}.root`),
    voteMap,
    voteIndex: index,
  };
}

export function nativeProcessMessageTransitionContexts(stateResult) {
  const stateNodeMap = new Map();
  const voteNodeMaps = new Map();
  const contexts = Array.from({ length: stateResult.transitions.length });
  const initialTouchedStates = new Map();

  for (let index = stateResult.transitions.length - 1; index >= 0; index -= 1) {
    const transition = stateResult.transitions[index];
    const stateIndex = transition.derived.stateIndex.toString();
    if (!initialTouchedStates.has(stateIndex)) {
      const roots = nativeProcessMessageTransitionRoots(transition);
      initialTouchedStates.set(stateIndex, {
        transition,
        stateIndex: transition.derived.stateIndex,
        leafHash: roots.currentStateLeafHash,
      });
      stateNodeMap.set(mapKey(0, Number(transition.derived.stateIndex)), roots.currentStateLeafHash);
    }
  }

  for (const [label, entry] of initialTouchedStates.entries()) {
    const seeded = statePathFromMaps(
      stateNodeMap,
      entry.leafHash,
      entry.transition.input.stateLeafPathElements,
      entry.stateIndex,
      `initialState${label}`,
    );
    const { level1 } = splitIndex(entry.stateIndex);
    stateNodeMap.set(mapKey(1, level1), seeded.level1Node);
  }

  for (let index = stateResult.transitions.length - 1; index >= 0; index -= 1) {
    const transition = stateResult.transitions[index];
    const { input, derived } = transition;
    const stateIndex = derived.stateIndex;
    const voteOptionIndex = derived.voteOptionIndex;

    const currentVote = votePathFromMap(
      voteNodeMaps,
      stateIndex,
      input.currentVoteWeight,
      input.currentVoteWeightsPathElements,
      voteOptionIndex,
      `transition${index}.currentVote`,
    );
    const currentStateLeaf = nativeCurrentStateLeaf(input, currentVote.root);
    const currentStateLeafHash = nativeHash10(currentStateLeaf, `transition${index}.currentStateLeaf`);
    const currentState = statePathFromMaps(
      stateNodeMap,
      currentStateLeafHash,
      input.stateLeafPathElements,
      stateIndex,
      `transition${index}.currentState`,
    );

    const newVote = votePathFromMap(
      voteNodeMaps,
      stateIndex,
      derived.updatedVoteWeight,
      input.currentVoteWeightsPathElements,
      voteOptionIndex,
      `transition${index}.newVote`,
    );
    const newStateLeaf = nativeNewStateLeaf(
      input,
      derived,
      currentStateLeaf[3],
      newVote.root,
    );
    const newStateLeafHash = nativeHash10(newStateLeaf, `transition${index}.newStateLeaf`);
    const newState = statePathFromMaps(
      stateNodeMap,
      newStateLeafHash,
      input.stateLeafPathElements,
      stateIndex,
      `transition${index}.newState`,
    );

    updateStateMaps(
      stateNodeMap,
      stateIndex,
      newState.level0Children,
      newState.level1Children,
      newStateLeafHash,
    );
    newVote.voteMap.set(newVote.voteIndex, toStarkFelt(derived.updatedVoteWeight, `transition${index}.updatedVoteWeight`));

    contexts[index] = {
      currentVoteRoot: currentVote.root,
      newVoteOptionRoot: newVote.root,
      currentVotePathElements: currentVote.path,
      currentStateLeaf,
      newStateLeaf,
      currentStateLeafHash,
      newStateLeafHash,
      currentStateRoot: currentState.root,
      newStateRoot: newState.root,
      stateLeafPathElements: currentState.path,
      activeStateRoot: toStarkFelt(input.activeStateRoot, `transition${index}.activeStateRoot`),
    };
  }

  return contexts;
}
