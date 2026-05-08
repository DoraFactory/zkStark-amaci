import { TREE_ARITY } from '../constants.mjs';
import { parseBigInt } from './encoding.mjs';
import { hash5 } from './poseidon.mjs';

export function expectedLeafCount(depth) {
  return TREE_ARITY ** depth;
}

export function quinaryRoot(leaves, depth) {
  if (!Number.isInteger(depth) || depth <= 0) {
    throw new Error('quinaryRoot depth must be a positive integer');
  }
  const expected = expectedLeafCount(depth);
  if (!Array.isArray(leaves) || leaves.length !== expected) {
    throw new Error(`quinaryRoot depth ${depth} expects ${expected} leaves`);
  }

  let level = leaves.map((value, idx) => parseBigInt(value, `leaves[${idx}]`));
  for (let d = 0; d < depth; d += 1) {
    const next = [];
    for (let i = 0; i < level.length; i += TREE_ARITY) {
      next.push(hash5(level.slice(i, i + TREE_ARITY)));
    }
    level = next;
  }
  if (level.length !== 1) {
    throw new Error('invalid quinary tree reduction');
  }
  return level[0];
}

export function zeroRoot(depth) {
  if (!Number.isInteger(depth) || depth <= 0) {
    throw new Error('zeroRoot depth must be a positive integer');
  }
  let zero = 0n;
  for (let i = 0; i < depth; i += 1) {
    zero = hash5([zero, zero, zero, zero, zero]);
  }
  return zero;
}

export function pathIndices(index, levels) {
  let cursor = parseBigInt(index, 'index');
  const out = [];
  for (let i = 0; i < levels; i += 1) {
    out.push(Number(cursor % BigInt(TREE_ARITY)));
    cursor /= BigInt(TREE_ARITY);
  }
  if (cursor !== 0n) {
    throw new Error(`index ${index.toString()} does not fit in ${levels} quinary levels`);
  }
  return out;
}

export function quinaryInclusionRoot(leaf, pathElements, index) {
  if (!Array.isArray(pathElements)) {
    throw new Error('pathElements must be an array');
  }

  const indices = pathIndices(index, pathElements.length);
  let node = parseBigInt(leaf, 'leaf');

  for (let level = 0; level < pathElements.length; level += 1) {
    const siblings = pathElements[level];
    if (!Array.isArray(siblings) || siblings.length !== TREE_ARITY - 1) {
      throw new Error(`pathElements[${level}] must contain ${TREE_ARITY - 1} siblings`);
    }
    const idx = indices[level];
    const children = [];
    let siblingIndex = 0;
    for (let i = 0; i < TREE_ARITY; i += 1) {
      if (i === idx) {
        children.push(node);
      } else {
        children.push(parseBigInt(siblings[siblingIndex], `pathElements[${level}][${siblingIndex}]`));
        siblingIndex += 1;
      }
    }
    node = hash5(children);
  }

  return node;
}

