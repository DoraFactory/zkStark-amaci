import { createRequire } from 'node:module';
import { parseBigInt } from './encoding.mjs';
import { poseidonHashBn254 } from './poseidon-bn254.mjs';

let circomPoseidon;

function loadCircomPoseidon() {
  if (circomPoseidon) {
    return circomPoseidon;
  }

  try {
    const requireFromCircuits = createRequire(new URL('../../package.json', import.meta.url));
    ({ poseidon: circomPoseidon } = requireFromCircuits('circom'));
  } catch (error) {
    throw new Error(
      `Unable to load optional circom Poseidon package. ` +
        `The standalone implementation uses the pure JS BN254 Poseidon fallback. Cause: ${error.message}`,
    );
  }

  return circomPoseidon;
}

export function isCircomPoseidonAvailable() {
  try {
    loadCircomPoseidon();
    return true;
  } catch {
    return false;
  }
}

export function poseidonHash(inputs) {
  return poseidonHashBn254(inputs.map((value, idx) => parseBigInt(value, `poseidon[${idx}]`)));
}

export function poseidonHashFromCircom(inputs) {
  const poseidon = loadCircomPoseidon();
  return BigInt(poseidon(inputs.map((value, idx) => parseBigInt(value, `poseidon[${idx}]`))).toString());
}

export function hashLeftRight(left, right) {
  return poseidonHash([left, right]);
}

export function hash5(values) {
  if (!Array.isArray(values) || values.length !== 5) {
    throw new Error('hash5 expects exactly five values');
  }
  return poseidonHash(values);
}

export function hash10(values) {
  if (!Array.isArray(values) || values.length !== 10) {
    throw new Error('hash10 expects exactly ten values');
  }
  return hashLeftRight(hash5(values.slice(0, 5)), hash5(values.slice(5, 10)));
}

export function hash13(values) {
  if (!Array.isArray(values) || values.length !== 13) {
    throw new Error('hash13 expects exactly thirteen values');
  }
  return hash5([
    hash5(values.slice(0, 5)),
    hash5(values.slice(5, 10)),
    values[10],
    values[11],
    values[12],
  ]);
}
