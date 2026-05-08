import { createRequire } from 'node:module';
import { BN254_SCALAR_FIELD } from '../constants.mjs';
import { parseBigInt } from './encoding.mjs';

const requireFromCircuits = createRequire(new URL('../../../packages/circuits/package.json', import.meta.url));
const { C: RAW_C, M: RAW_M } = requireFromCircuits('circom/src/poseidon_constants.json');

const N_ROUNDS_F = 8;
const N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63];

function parseConstant(value) {
  if (typeof value === 'string') {
    return BigInt(value);
  }
  if (typeof value === 'number') {
    return BigInt(value);
  }
  throw new Error(`unsupported Poseidon constant value: ${value}`);
}

function deepMapConstants(value) {
  if (Array.isArray(value)) {
    return value.map(deepMapConstants);
  }
  return parseConstant(value);
}

const C = deepMapConstants(RAW_C);
const M = deepMapConstants(RAW_M);

export function bn254(value) {
  const normalized = parseBigInt(value) % BN254_SCALAR_FIELD;
  return normalized < 0n ? normalized + BN254_SCALAR_FIELD : normalized;
}

export function bn254Add(left, right) {
  return (left + right) % BN254_SCALAR_FIELD;
}

export function bn254Mul(left, right) {
  return (left * right) % BN254_SCALAR_FIELD;
}

export function bn254Pow5(value) {
  const x2 = bn254Mul(value, value);
  const x4 = bn254Mul(x2, x2);
  return bn254Mul(x4, value);
}

export function poseidonPermutationBn254(inputs) {
  if (!Array.isArray(inputs) || inputs.length === 0 || inputs.length >= N_ROUNDS_P.length) {
    throw new Error('poseidon permutation expects between 1 and 7 state elements');
  }

  const t = inputs.length;
  const nRoundsP = N_ROUNDS_P[t - 2];
  const roundConstants = C[t - 2];
  const mds = M[t - 2];
  let state = inputs.map((value, idx) => bn254(parseBigInt(value, `poseidonPerm[${idx}]`)));

  for (let round = 0; round < N_ROUNDS_F + nRoundsP; round += 1) {
    state = state.map((value, idx) => bn254Add(value, roundConstants[round * t + idx]));

    if (round < N_ROUNDS_F / 2 || round >= N_ROUNDS_F / 2 + nRoundsP) {
      state = state.map(bn254Pow5);
    } else {
      state[0] = bn254Pow5(state[0]);
    }

    state = state.map((_, row) =>
      state.reduce((sum, value, col) => bn254Add(sum, bn254Mul(mds[row][col], value)), 0n),
    );
  }

  return state;
}

export function poseidonHashBn254(inputs) {
  if (!Array.isArray(inputs) || inputs.length < 1 || inputs.length > 6) {
    throw new Error('poseidon hash expects between 1 and 6 inputs');
  }
  return poseidonPermutationBn254([0n, ...inputs])[0];
}

export function poseidon2Bn254(left, right) {
  return poseidonHashBn254([left, right]);
}

export function poseidon5Bn254(values) {
  if (!Array.isArray(values) || values.length !== 5) {
    throw new Error('poseidon5 expects exactly five inputs');
  }
  return poseidonHashBn254(values);
}
