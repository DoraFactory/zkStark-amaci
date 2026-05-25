import { TREE_ARITY } from './constants.mjs';
import { parseBigInt } from './encoding.mjs';
import { poseidonManyFelts } from './integrity/hashes.mjs';
import { toStarkFelt } from './tally/native-tally-votes.mjs';

export function nativeHashFelts(values, label = 'hash') {
  return poseidonManyFelts(values.map((value, index) => toStarkFelt(value, `${label}[${index}]`)));
}

export function nativeHashPoint(values, label = 'point') {
  if (!Array.isArray(values) || values.length !== 2) {
    throw new Error(`${label} must contain two values`);
  }
  return nativeHashFelts(values, label);
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
