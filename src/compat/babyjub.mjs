import { BN254_SCALAR_FIELD } from '../constants.mjs';
import { parseBigInt } from './encoding.mjs';
import { bn254, bn254Add, bn254Mul } from './poseidon-bn254.mjs';
import { hash5, poseidonHash } from './poseidon.mjs';

export const BABYJUB_A = 168700n;
export const BABYJUB_D = 168696n;
export const BABYJUB_IDENTITY = Object.freeze([0n, 1n]);
export const BABYJUB_BASE8 = Object.freeze([
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
]);
export const BABYJUB_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;
export const BABYJUB_SCALAR_BITS = 253;

export function bn254Sub(left, right) {
  return bn254(parseBigInt(left) - parseBigInt(right));
}

function modPow(base, exponent) {
  let result = 1n;
  let power = bn254(base);
  let remaining = parseBigInt(exponent, 'exponent');
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) {
      result = bn254Mul(result, power);
    }
    power = bn254Mul(power, power);
    remaining >>= 1n;
  }
  return result;
}

export function bn254Inv(value) {
  const normalized = bn254(value);
  if (normalized === 0n) {
    throw new Error('cannot invert zero in BN254 field');
  }
  return modPow(normalized, BN254_SCALAR_FIELD - 2n);
}

export function bn254Div(numerator, denominator) {
  return bn254Mul(bn254(numerator), bn254Inv(denominator));
}

export function babyjubAdd(left, right) {
  const [x1, y1] = left.map((value, idx) => bn254(parseBigInt(value, `left[${idx}]`)));
  const [x2, y2] = right.map((value, idx) => bn254(parseBigInt(value, `right[${idx}]`)));
  const beta = bn254Mul(x1, y2);
  const gamma = bn254Mul(y1, x2);
  const delta = bn254Mul(bn254Sub(y1, bn254Mul(BABYJUB_A, x1)), bn254Add(x2, y2));
  const tau = bn254Mul(beta, gamma);
  const dtau = bn254Mul(BABYJUB_D, tau);
  const x = bn254Div(bn254Add(beta, gamma), bn254Add(1n, dtau));
  const y = bn254Div(
    bn254Add(delta, bn254Sub(bn254Mul(BABYJUB_A, beta), gamma)),
    bn254Sub(1n, dtau),
  );
  return [x, y];
}

export function babyjubDouble(point) {
  return babyjubAdd(point, point);
}

export function babyjubNegate(point) {
  const [x, y] = point.map((value, idx) => bn254(parseBigInt(value, `point[${idx}]`)));
  return [bn254Sub(0n, x), y];
}

export function babyjubScalarMul(base, scalar, bitLength = BABYJUB_SCALAR_BITS) {
  let acc = [...BABYJUB_IDENTITY];
  let exp = base.map((value, idx) => bn254(parseBigInt(value, `base[${idx}]`)));
  const n = parseBigInt(scalar, 'scalar');
  for (let i = 0; i < bitLength; i += 1) {
    if (((n >> BigInt(i)) & 1n) === 1n) {
      acc = babyjubAdd(acc, exp);
    }
    exp = babyjubDouble(exp);
  }
  return acc;
}

export function buildBabyjubScalarMulTranscript(base, scalar, bitLength = BABYJUB_SCALAR_BITS) {
  let acc = [...BABYJUB_IDENTITY];
  let exp = base.map((value, idx) => bn254(parseBigInt(value, `base[${idx}]`)));
  const n = parseBigInt(scalar, 'scalar');
  const steps = [];
  let reconstructed = 0n;
  let power = 1n;

  for (let i = 0; i < bitLength; i += 1) {
    const bit = (n >> BigInt(i)) & 1n;
    const sum = babyjubAdd(acc, exp);
    const nextExp = babyjubDouble(exp);
    const nextAcc = bit === 1n ? sum : acc;
    steps.push({
      bit,
      sum,
      nextAcc,
      nextExp,
    });
    reconstructed += bit * power;
    power <<= 1n;
    acc = nextAcc;
    exp = nextExp;
  }

  if (reconstructed !== n) {
    throw new Error('scalar does not fit in transcript bit length');
  }

  return {
    bitLength,
    scalar: n,
    base,
    expected: acc,
    steps,
  };
}

export function buildEcdhSharedKeyWitness(privKey, pubKey) {
  return buildBabyjubScalarMulTranscript(pubKey, privKey, BABYJUB_SCALAR_BITS);
}

export function buildElGamalDecryptWitness({ privKey, c1, c2 }) {
  const parsedC1 = c1.map((value, idx) => bn254(parseBigInt(value, `c1[${idx}]`)));
  const parsedC2 = c2.map((value, idx) => bn254(parseBigInt(value, `c2[${idx}]`)));
  const scalarMul = buildBabyjubScalarMulTranscript(parsedC1, privKey, BABYJUB_SCALAR_BITS);
  const c1x = verifyBabyjubScalarMulTranscript(scalarMul, BABYJUB_SCALAR_BITS);
  const decryptedPoint = babyjubAdd(babyjubNegate(c1x), parsedC2);
  return {
    scalarMul,
    c1x,
    decryptedPoint,
    isOdd: decryptedPoint[0] & 1n,
  };
}

export function verifyBabyjubScalarMulTranscript(witness, bitLength = witness.bitLength ?? BABYJUB_SCALAR_BITS) {
  const scalar = parseBigInt(witness.scalar, 'scalar');
  let acc = [...BABYJUB_IDENTITY];
  let exp = witness.base.map((value, idx) => bn254(parseBigInt(value, `base[${idx}]`)));
  let reconstructed = 0n;
  let power = 1n;

  if (!Array.isArray(witness.steps) || witness.steps.length !== bitLength) {
    throw new Error(`steps must contain ${bitLength} values`);
  }

  for (let i = 0; i < witness.steps.length; i += 1) {
    const step = witness.steps[i];
    const bit = parseBigInt(step.bit, `steps[${i}].bit`);
    if (bit !== 0n && bit !== 1n) {
      throw new Error(`steps[${i}].bit must be 0 or 1`);
    }
    const expectedSum = babyjubAdd(acc, exp);
    const expectedNextExp = babyjubDouble(exp);
    const expectedNextAcc = bit === 1n ? expectedSum : acc;
    for (let j = 0; j < 2; j += 1) {
      const sum = parseBigInt(step.sum[j], `steps[${i}].sum[${j}]`);
      const nextAcc = parseBigInt(step.nextAcc[j], `steps[${i}].nextAcc[${j}]`);
      const nextExp = parseBigInt(step.nextExp[j], `steps[${i}].nextExp[${j}]`);
      if (sum !== expectedSum[j]) {
        throw new Error(`steps[${i}].sum[${j}] mismatch`);
      }
      if (nextAcc !== expectedNextAcc[j]) {
        throw new Error(`steps[${i}].nextAcc[${j}] mismatch`);
      }
      if (nextExp !== expectedNextExp[j]) {
        throw new Error(`steps[${i}].nextExp[${j}] mismatch`);
      }
    }
    reconstructed += bit * power;
    power <<= 1n;
    acc = expectedNextAcc;
    exp = expectedNextExp;
  }

  if (reconstructed !== scalar) {
    throw new Error('scalar reconstruction mismatch');
  }
  for (let i = 0; i < 2; i += 1) {
    const expected = parseBigInt(witness.expected[i], `expected[${i}]`);
    if (expected !== acc[i]) {
      throw new Error(`expected[${i}] mismatch`);
    }
  }

  return acc;
}

function pointsEqual(left, right) {
  return left[0] === right[0] && left[1] === right[1];
}

export function poseidonSignatureMessage(preimage) {
  if (!Array.isArray(preimage) || preimage.length !== 3) {
    throw new Error('signature preimage must contain three values');
  }
  return poseidonHash(preimage);
}

export function poseidonSignatureChallenge({ pubKey, r8, preimage }) {
  if (!Array.isArray(pubKey) || pubKey.length !== 2) {
    throw new Error('pubKey must contain two values');
  }
  if (!Array.isArray(r8) || r8.length !== 2) {
    throw new Error('r8 must contain two values');
  }
  return hash5([...r8, ...pubKey, poseidonSignatureMessage(preimage)]);
}

export function buildBabyjubPoseidonSignatureWitness({ pubKey, r8, s, preimage }) {
  const parsedPubKey = pubKey.map((value, idx) => bn254(parseBigInt(value, `pubKey[${idx}]`)));
  const parsedR8 = r8.map((value, idx) => bn254(parseBigInt(value, `r8[${idx}]`)));
  const parsedS = parseBigInt(s, 's');
  const parsedPreimage = preimage.map((value, idx) => bn254(parseBigInt(value, `preimage[${idx}]`)));
  const pubKeyX2 = babyjubDouble(parsedPubKey);
  const pubKeyX4 = babyjubDouble(pubKeyX2);
  const pubKeyX8 = babyjubDouble(pubKeyX4);
  const challenge = poseidonSignatureChallenge({
    pubKey: parsedPubKey,
    r8: parsedR8,
    preimage: parsedPreimage,
  });
  const sBase8 = buildBabyjubScalarMulTranscript(BABYJUB_BASE8, parsedS, BABYJUB_SCALAR_BITS);
  const hPubKeyX8 = buildBabyjubScalarMulTranscript(pubKeyX8, challenge, 254);
  const right2 = verifyBabyjubScalarMulTranscript(hPubKeyX8, 254);
  const right = babyjubAdd(parsedR8, right2);
  const left = verifyBabyjubScalarMulTranscript(sBase8, BABYJUB_SCALAR_BITS);
  const valid =
    pointsEqual(left, right) && pubKeyX8[0] !== 0n && parsedS < BABYJUB_SUBGROUP_ORDER ? 1n : 0n;

  return {
    pubKey: parsedPubKey,
    r8: parsedR8,
    s: parsedS,
    preimage: parsedPreimage,
    messageHash: poseidonSignatureMessage(parsedPreimage),
    challenge,
    valid,
    pubKeyX2,
    pubKeyX4,
    pubKeyX8,
    sBase8,
    hPubKeyX8,
    right,
  };
}

export function verifyBabyjubPoseidonSignatureWitness(witness) {
  const recomputed = buildBabyjubPoseidonSignatureWitness({
    pubKey: witness.pubKey,
    r8: witness.r8,
    s: witness.s,
    preimage: witness.preimage,
  });
  if (!pointsEqual(recomputed.pubKeyX2, witness.pubKeyX2.map(BigInt))) {
    throw new Error('pubKeyX2 mismatch');
  }
  if (!pointsEqual(recomputed.pubKeyX4, witness.pubKeyX4.map(BigInt))) {
    throw new Error('pubKeyX4 mismatch');
  }
  if (!pointsEqual(recomputed.pubKeyX8, witness.pubKeyX8.map(BigInt))) {
    throw new Error('pubKeyX8 mismatch');
  }
  if (!pointsEqual(recomputed.right, witness.right.map(BigInt))) {
    throw new Error('signature right point mismatch');
  }
  verifyBabyjubScalarMulTranscript(witness.sBase8, BABYJUB_SCALAR_BITS);
  verifyBabyjubScalarMulTranscript(witness.hPubKeyX8, 254);
  return recomputed.valid;
}
