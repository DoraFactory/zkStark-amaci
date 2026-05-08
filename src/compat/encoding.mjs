import { createHash } from 'node:crypto';
import { BN254_SCALAR_FIELD, U128_MODULUS, U256_MODULUS } from '../constants.mjs';

export function parseBigInt(value, label = 'value') {
  if (typeof value === 'bigint') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative safe integer`);
    }
    return BigInt(value);
  }
  if (typeof value === 'string') {
    if (value.length === 0) {
      throw new Error(`${label} must not be empty`);
    }
    return value.startsWith('0x') || value.startsWith('0X') ? BigInt(value) : BigInt(value);
  }
  throw new Error(`${label} must be a bigint, number, or decimal/hex string`);
}

export function assertUint256(value, label = 'value') {
  const n = parseBigInt(value, label);
  if (n < 0n || n >= U256_MODULUS) {
    throw new Error(`${label} is outside uint256 range`);
  }
  return n;
}

export function bigintToBytes32(value, label = 'value') {
  const n = assertUint256(value, label);
  const hex = n.toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}

export function sha256Uint256List(values) {
  const bytes = Buffer.concat(values.map((value, idx) => bigintToBytes32(value, `values[${idx}]`)));
  return BigInt(`0x${createHash('sha256').update(bytes).digest('hex')}`);
}

export function tallyInputHash(packedVals, stateCommitment, currentTallyCommitment, newTallyCommitment) {
  return (
    sha256Uint256List([
      packedVals,
      stateCommitment,
      currentTallyCommitment,
      newTallyCommitment,
    ]) % BN254_SCALAR_FIELD
  );
}

export function splitU256ToU128(value, label = 'value') {
  const n = assertUint256(value, label);
  return {
    low: n % U128_MODULUS,
    high: n / U128_MODULUS,
  };
}

export function joinU128Pair(low, high, label = 'u256') {
  const lo = parseBigInt(low, `${label}.low`);
  const hi = parseBigInt(high, `${label}.high`);
  if (lo < 0n || lo >= U128_MODULUS || hi < 0n || hi >= U128_MODULUS) {
    throw new Error(`${label} limbs must be uint128`);
  }
  return lo + hi * U128_MODULUS;
}

export function bigintToHex(value) {
  return `0x${parseBigInt(value).toString(16)}`;
}

export function decimalize(value) {
  return parseBigInt(value).toString(10);
}

export function deepMapBigInt(value) {
  if (Array.isArray(value)) {
    return value.map(deepMapBigInt);
  }
  return parseBigInt(value);
}

