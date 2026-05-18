import { TREE_ARITY } from '../constants.mjs';
import { parseBigInt } from '../compat/encoding.mjs';
import { poseidonManyFelts } from '../integrity/hashes.mjs';
import { nativeHash5, nativeHash10 } from '../msg/native-process-roots.mjs';
import { toStarkFelt } from '../tally/native-tally-votes.mjs';

function mapKey(level, index) {
  return `${level}:${index}`;
}

function splitIndex(index, depth) {
  let cursor = parseBigInt(index, 'index');
  const out = [];
  for (let level = 0; level < depth; level += 1) {
    out.push(Number(cursor % BigInt(TREE_ARITY)));
    cursor /= BigInt(TREE_ARITY);
  }
  return out;
}

function repeated(value) {
  return Array.from({ length: TREE_ARITY }, () => value);
}

function zeroRoots(leaf) {
  const roots = [leaf];
  for (let level = 1; level <= 4; level += 1) {
    roots.push(nativeHash5(repeated(roots[level - 1]), `zeroRoot${level}`));
  }
  return roots;
}

function pathFromMap(nodeMap, depth, leaf, index, fallbackRoots, label) {
  const indices = splitIndex(index, depth);
  let node = toStarkFelt(leaf, `${label}.leaf`);
  const path = [];
  const levelChildren = [];

  for (let level = 0; level < depth; level += 1) {
    const levelIndex = indices[level];
    const nodeIndexAtLevel = Math.floor(Number(parseBigInt(index, `${label}.index`)) / (TREE_ARITY ** level));
    const groupStart = nodeIndexAtLevel - levelIndex;
    const children = [];
    const pathLevel = [];
    for (let offset = 0; offset < TREE_ARITY; offset += 1) {
      const absoluteIndex = groupStart + offset;
      if (offset === levelIndex) {
        children.push(node);
      } else {
        const value = nodeMap.get(mapKey(level, absoluteIndex)) ?? fallbackRoots[level];
        children.push(value);
        pathLevel.push(value);
      }
    }
    path.push(pathLevel);
    levelChildren.push(children);
    node = nativeHash5(children, `${label}.level${level}`);
  }

  return {
    path,
    root: node,
    levelChildren,
  };
}

function updateMap(nodeMap, depth, index, leaf, context) {
  let cursor = Number(parseBigInt(index, 'index'));
  nodeMap.set(mapKey(0, cursor), leaf);
  for (let level = 1; level <= depth; level += 1) {
    cursor = Math.floor(cursor / TREE_ARITY);
    nodeMap.set(mapKey(level, cursor), nativeHash5(context.levelChildren[level - 1], `update${level}`));
  }
}

function nativeDeactivateLeaf(input, sharedKeyHash) {
  return nativeHash5([
    input.c1[0],
    input.c1[1],
    input.c2[0],
    input.c2[1],
    sharedKeyHash,
  ], 'deactivateLeaf');
}

function nativeHashPoint(values, label) {
  if (!Array.isArray(values) || values.length !== 2) {
    throw new Error(`${label} must contain two values`);
  }
  return poseidonManyFelts(values.map((value, index) => toStarkFelt(value, `${label}[${index}]`)));
}

export function nativeProcessDeactivateTransitionContexts(stateResult) {
  const emptyStateLeafHash = nativeHash10(Array.from({ length: 10 }, () => 0n), 'emptyStateLeaf');
  const stateFallback = zeroRoots(emptyStateLeafHash);
  const activeFallback = zeroRoots(0n);
  const deactivateFallback = zeroRoots(0n);
  const stateMap = new Map();
  const activeMap = new Map();
  const deactivateMap = new Map();

  for (const transition of stateResult.transitions) {
    const stateIndex = Number(transition.derived.stateIndex);
    stateMap.set(mapKey(0, stateIndex), nativeHash10(transition.input.stateLeaf, `initialState${stateIndex}`));
  }
  for (const transition of stateResult.transitions) {
    const stateIndex = Number(transition.derived.stateIndex);
    const seeded = pathFromMap(
      stateMap,
      2,
      nativeHash10(transition.input.stateLeaf, `seedState${stateIndex}`),
      stateIndex,
      stateFallback,
      `seedStatePath${stateIndex}`,
    );
    const group = Math.floor(stateIndex / TREE_ARITY);
    stateMap.set(mapKey(1, group), nativeHash5(seeded.levelChildren[0], `seedStateGroup${group}`));
  }

  return stateResult.transitions.map((transition, messageIndex) => {
    const input = transition.input;
    const stateIndex = transition.derived.stateIndex;
    const deactivateIndex = input.deactivateIndex;
    const stateLeafHash = nativeHash10(input.stateLeaf, `deactivate${messageIndex}.stateLeaf`);
    const statePath = pathFromMap(
      stateMap,
      2,
      stateLeafHash,
      stateIndex,
      stateFallback,
      `deactivate${messageIndex}.state`,
    );
    const currentActivePath = pathFromMap(
      activeMap,
      2,
      input.currentActiveState,
      stateIndex,
      activeFallback,
      `deactivate${messageIndex}.currentActive`,
    );
    const newActiveLeaf = transition.derived.valid === 1n
      ? input.newActiveState
      : input.currentActiveState;
    const newActivePath = pathFromMap(
      activeMap,
      2,
      newActiveLeaf,
      stateIndex,
      activeFallback,
      `deactivate${messageIndex}.newActive`,
    );
    const currentDeactivatePath = pathFromMap(
      deactivateMap,
      4,
      0n,
      deactivateIndex,
      deactivateFallback,
      `deactivate${messageIndex}.currentDeactivate`,
    );
    const sharedKeyHash = nativeHashPoint(transition.derived.sharedKey, 'deactivateSharedKey');
    const newDeactivateLeaf = input.isEmptyMsg === 1n ? 0n : nativeDeactivateLeaf(input, sharedKeyHash);
    const newDeactivatePath = pathFromMap(
      deactivateMap,
      4,
      newDeactivateLeaf,
      deactivateIndex,
      deactivateFallback,
      `deactivate${messageIndex}.newDeactivate`,
    );

    updateMap(activeMap, 2, stateIndex, toStarkFelt(newActiveLeaf, 'newActiveLeaf'), newActivePath);
    updateMap(deactivateMap, 4, deactivateIndex, newDeactivateLeaf, newDeactivatePath);

    return {
      currentStateRoot: statePath.root,
      currentActiveStateRoot: currentActivePath.root,
      newActiveStateRoot: newActivePath.root,
      currentDeactivateRoot: currentDeactivatePath.root,
      newDeactivateRoot: newDeactivatePath.root,
      stateLeafPathElements: statePath.path,
      activeStateLeafPathElements: currentActivePath.path,
      deactivateLeafPathElements: currentDeactivatePath.path,
      deactivateLeaf: newDeactivateLeaf,
    };
  });
}

export function nativeProcessDeactivateStateRoots(stateResult) {
  const contexts = nativeProcessDeactivateTransitionContexts(stateResult);
  return {
    transitionRoots: contexts,
    currentStateRoot: contexts[0].currentStateRoot,
    currentActiveStateRoot: contexts[0].currentActiveStateRoot,
    currentDeactivateRoot: contexts[0].currentDeactivateRoot,
    newActiveStateRoot: contexts.at(-1).newActiveStateRoot,
    newDeactivateRoot: contexts.at(-1).newDeactivateRoot,
  };
}
