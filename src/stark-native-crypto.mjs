import { ec } from 'starknet';
import { parseBigInt } from './encoding.mjs';
import {
  STARK_FIELD,
  STARK_NATIVE_COMMAND_SIGNATURE_DOMAIN,
  STARK_NATIVE_COMMAND_STREAM_DOMAIN,
  STARK_NATIVE_DEACTIVATE_SIGNATURE_DOMAIN,
  STARK_NATIVE_DEACTIVATE_STREAM_DOMAIN,
} from './constants.mjs';
import { poseidonManyFelts } from './integrity/hashes.mjs';

export {
  STARK_NATIVE_COMMAND_SIGNATURE_DOMAIN,
  STARK_NATIVE_COMMAND_STREAM_DOMAIN,
  STARK_NATIVE_DEACTIVATE_SIGNATURE_DOMAIN,
  STARK_NATIVE_DEACTIVATE_STREAM_DOMAIN,
};

export const STARK_CURVE_ORDER =
  3618502788666131213697322783095070105526743751716087489154079457884512865583n;
const STARK_NATIVE_ECDSA_NONCE_DOMAIN = 0x414d4143495f535441524b5f45434453415f4e4f4e4345n; // AMACI_STARK_ECDSA_NONCE

function mod(value, modulus) {
  const result = parseBigInt(value) % modulus;
  return result >= 0n ? result : result + modulus;
}

function normalizeScalar(value, label = 'scalar') {
  const scalar = mod(parseBigInt(value, label), STARK_CURVE_ORDER);
  if (scalar === 0n) {
    throw new Error(`${label} must be non-zero modulo the STARK curve order`);
  }
  return scalar;
}

function normalizeFelt(value, label = 'felt') {
  const felt = parseBigInt(value, label);
  if (felt < 0n || felt >= STARK_FIELD) {
    throw new Error(`${label} must be a STARK field element`);
  }
  return felt;
}

function feltAdd(left, right) {
  return (normalizeFelt(left, 'left') + normalizeFelt(right, 'right')) % STARK_FIELD;
}

function feltSub(left, right) {
  const value = normalizeFelt(left, 'left') - normalizeFelt(right, 'right');
  return value >= 0n ? value : value + STARK_FIELD;
}

function scalarHex(value, label = 'scalar') {
  return `0x${normalizeScalar(value, label).toString(16).padStart(64, '0')}`;
}

function msgHex(value, label = 'messageHash') {
  return `0x${normalizeFelt(value, label).toString(16).padStart(64, '0')}`;
}

function pointToPair(point) {
  const affine = point.toAffine();
  return [affine.x, affine.y];
}

function pointFromPair(point, label = 'point') {
  if (!Array.isArray(point) || point.length !== 2) {
    throw new Error(`${label} must contain two coordinates`);
  }
  return ec.starkCurve.ProjectivePoint.fromAffine({
    x: normalizeFelt(point[0], `${label}[0]`),
    y: normalizeFelt(point[1], `${label}[1]`),
  });
}

function modInverse(value, modulus) {
  let low = mod(value, modulus);
  if (low === 0n) {
    throw new Error('cannot invert zero');
  }
  let high = modulus;
  let lm = 1n;
  let hm = 0n;
  while (low > 1n) {
    const ratio = high / low;
    const next = high - low * ratio;
    const nextM = hm - lm * ratio;
    high = low;
    hm = lm;
    low = next;
    lm = nextM;
  }
  return mod(lm, modulus);
}

export function starkPublicKeyPoint(privateKey) {
  return pointToPair(ec.starkCurve.ProjectivePoint.BASE.multiply(normalizeScalar(privateKey, 'privateKey')));
}

export function starkScalarMul(point, scalar) {
  return pointToPair(pointFromPair(point, 'point').multiply(normalizeScalar(scalar)));
}

export function starkPointAdd(left, right) {
  return pointToPair(pointFromPair(left, 'left').add(pointFromPair(right, 'right')));
}

export function starkPointNegate(point) {
  return pointToPair(pointFromPair(point, 'point').negate());
}

export function starkPointSub(left, right) {
  return pointToPair(pointFromPair(left, 'left').subtract(pointFromPair(right, 'right')));
}

export function starkPointWithXParity(parity, seed = 1n) {
  const expected = parseBigInt(parity, 'parity');
  if (expected !== 0n && expected !== 1n) {
    throw new Error('parity must be 0 or 1');
  }
  let scalar = normalizeScalar(seed, 'seed');
  for (let i = 0; i < 1000; i += 1) {
    const point = starkPublicKeyPoint(scalar);
    if ((point[0] & 1n) === expected) {
      return { scalar, point };
    }
    scalar = normalizeScalar(scalar + 1n, 'seed');
  }
  throw new Error('failed to find STARK curve point with requested x parity');
}

export function starkElGamalEncryptPoint(plainPoint, publicKey, randomScalar) {
  const c1 = starkPublicKeyPoint(randomScalar);
  const shared = starkScalarMul(publicKey, randomScalar);
  const c2 = starkPointAdd(plainPoint, shared);
  return { c1, c2, shared };
}

export function starkElGamalDecryptPoint(c1, c2, privateKey) {
  const shared = starkScalarMul(c1, privateKey);
  const decryptedPoint = starkPointSub(c2, shared);
  return {
    c1x: shared,
    decryptedPoint,
    isOdd: decryptedPoint[0] & 1n,
  };
}

export function starkCommandSignatureHash(packedCommand, cmdSalt, domain = STARK_NATIVE_COMMAND_SIGNATURE_DOMAIN) {
  if (!Array.isArray(packedCommand) || packedCommand.length !== 3) {
    throw new Error('packedCommand must contain three values');
  }
  return poseidonManyFelts([
    domain,
    normalizeFelt(packedCommand[0], 'packedCommand[0]'),
    normalizeFelt(packedCommand[1], 'packedCommand[1]'),
    normalizeFelt(packedCommand[2], 'packedCommand[2]'),
    normalizeFelt(cmdSalt, 'cmdSalt'),
  ]);
}

export function starkSignCommand(privateKey, packedCommand, cmdSalt, domain = STARK_NATIVE_COMMAND_SIGNATURE_DOMAIN) {
  const messageHash = starkCommandSignatureHash(packedCommand, cmdSalt, domain);
  const secret = normalizeScalar(privateKey, 'privateKey');
  let nonce = mod(
    poseidonManyFelts([
      STARK_NATIVE_ECDSA_NONCE_DOMAIN,
      normalizeFelt(domain, 'domain'),
      secret,
      messageHash,
      normalizeFelt(cmdSalt, 'cmdSalt'),
    ]),
    STARK_CURVE_ORDER,
  );
  if (nonce === 0n) {
    nonce = 1n;
  }
  const rPoint = starkPublicKeyPoint(nonce);
  const r = normalizeScalar(rPoint[0], 'signature.r');
  const s = mod(modInverse(nonce, STARK_CURVE_ORDER) * mod(messageHash + r * secret, STARK_CURVE_ORDER), STARK_CURVE_ORDER);
  if (s === 0n) {
    throw new Error('derived zero STARK ECDSA signature scalar');
  }
  return {
    messageHash,
    r,
    rPoint,
    s,
  };
}

export function starkVerifyCommandSignature(
  publicKey,
  signature,
  packedCommand,
  cmdSalt,
  domain = STARK_NATIVE_COMMAND_SIGNATURE_DOMAIN,
) {
  const messageHash = starkCommandSignatureHash(packedCommand, cmdSalt, domain);
  const rPoint = pointFromPair(signature.rPoint ?? signature.r8 ?? [signature.r, signature.recovery ?? 0n], 'signature.rPoint');
  const publicPoint = pointFromPair(publicKey, 'publicKey');
  const r = normalizeScalar(signature.r ?? rPoint.toAffine().x, 'signature.r');
  const s = normalizeScalar(signature.s, 'signature.s');
  const left = rPoint.multiply(s);
  const right = ec.starkCurve.ProjectivePoint.BASE
    .multiply(normalizeScalar(messageHash, 'messageHash'))
    .add(publicPoint.multiply(r));
  return left.equals(right) ? 1n : 0n;
}

export function starkPoseidonStreamValue(
  sharedKey,
  nonce,
  index,
  domain = STARK_NATIVE_COMMAND_STREAM_DOMAIN,
) {
  if (!Array.isArray(sharedKey) || sharedKey.length !== 2) {
    throw new Error('sharedKey must contain two values');
  }
  return poseidonManyFelts([
    normalizeFelt(domain, 'domain'),
    normalizeFelt(sharedKey[0], 'sharedKey[0]'),
    normalizeFelt(sharedKey[1], 'sharedKey[1]'),
    normalizeFelt(nonce, 'nonce'),
    normalizeFelt(index, 'index'),
  ]);
}

export function starkPoseidonEncryptWithoutCheck7(
  decryptedCommand,
  sharedKey,
  nonce = 0n,
  domain = STARK_NATIVE_COMMAND_STREAM_DOMAIN,
) {
  if (!Array.isArray(decryptedCommand) || decryptedCommand.length !== 7) {
    throw new Error('decryptedCommand must contain seven values');
  }
  const plaintext = decryptedCommand.map((value, index) =>
    normalizeFelt(value, `decryptedCommand[${index}]`),
  );
  const ciphertext = [];
  for (let index = 0; index < 9; index += 1) {
    const stream = starkPoseidonStreamValue(sharedKey, nonce, BigInt(index), domain);
    const plain = index < plaintext.length ? plaintext[index] : 0n;
    ciphertext.push(feltAdd(plain, stream));
  }
  ciphertext.push(0n);
  return ciphertext;
}

export function starkPoseidonDecryptWithoutCheck7(
  message,
  sharedKey,
  nonce = 0n,
  domain = STARK_NATIVE_COMMAND_STREAM_DOMAIN,
) {
  if (!Array.isArray(message) || message.length !== 10) {
    throw new Error('message must contain ten values');
  }
  const decrypted = [];
  for (let index = 0; index < 9; index += 1) {
    const stream = starkPoseidonStreamValue(sharedKey, nonce, BigInt(index), domain);
    decrypted.push(feltSub(message[index], stream));
  }
  if (normalizeFelt(message[9], 'message[9]') !== 0n) {
    throw new Error('message[9] must be zero');
  }
  if (decrypted[7] !== 0n || decrypted[8] !== 0n) {
    throw new Error('encrypted command padding must decrypt to zero');
  }
  return decrypted.slice(0, 7);
}
