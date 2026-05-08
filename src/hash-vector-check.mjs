import { BN254_SCALAR_FIELD } from './constants.mjs';
import { parseBigInt, sha256Uint256List } from './compat/encoding.mjs';
import { poseidon2Bn254, poseidon5Bn254 } from './compat/poseidon-bn254.mjs';
import { hash10 } from './compat/poseidon.mjs';

function vectorInputs(vector) {
  if (!Array.isArray(vector.inputs)) {
    throw new Error(`${vector.id ?? 'hash vector'} inputs must be an array`);
  }
  return vector.inputs.map((value, idx) => parseBigInt(value, `${vector.id}.inputs[${idx}]`));
}

export function evaluateHashVector(vector) {
  const inputs = vectorInputs(vector);
  if (vector.type === 'poseidon2') {
    if (inputs.length !== 2) {
      throw new Error(`${vector.id} poseidon2 vector must have two inputs`);
    }
    return poseidon2Bn254(inputs[0], inputs[1]);
  }
  if (vector.type === 'poseidon5') {
    if (inputs.length !== 5) {
      throw new Error(`${vector.id} poseidon5 vector must have five inputs`);
    }
    return poseidon5Bn254(inputs);
  }
  if (vector.type === 'poseidon10') {
    if (inputs.length !== 10) {
      throw new Error(`${vector.id} poseidon10 vector must have ten inputs`);
    }
    return hash10(inputs);
  }
  if (vector.type === 'sha256_u256x4_mod_bn254') {
    if (inputs.length !== 4) {
      throw new Error(`${vector.id} sha256_u256x4_mod_bn254 vector must have four inputs`);
    }
    return sha256Uint256List(inputs) % BN254_SCALAR_FIELD;
  }
  throw new Error(`${vector.id ?? 'hash vector'} has unsupported type ${vector.type}`);
}

export function verifyHashVector(vector) {
  const expected = parseBigInt(vector.output, `${vector.id}.output`);
  const actual = evaluateHashVector(vector);
  if (actual !== expected) {
    throw new Error(
      `${vector.id} ${vector.type} mismatch: expected ${expected.toString()}, got ${actual.toString()}`,
    );
  }
  return actual;
}

export function verifyHashVectors(vectors) {
  if (!Array.isArray(vectors)) {
    throw new Error('hash vectors must be an array');
  }
  return vectors.map(verifyHashVector);
}
