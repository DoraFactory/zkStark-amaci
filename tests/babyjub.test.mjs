import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BABYJUB_BASE8,
  BABYJUB_SCALAR_BITS,
  babyjubScalarMul,
  buildBabyjubPoseidonSignatureWitness,
  buildEcdhSharedKeyWitness,
  poseidonSignatureMessage,
  verifyBabyjubPoseidonSignatureWitness,
  verifyBabyjubScalarMulTranscript,
} from '../src/compat/babyjub.mjs';
import {
  buildCairoBabyjubPoseidonSignatureInput,
  buildCairoEcdhSharedKeyInput,
  serializeCairoBabyjubPoseidonSignatureExecutableArgs,
  serializeCairoBabyjubScalarMulExecutableArgs,
} from '../src/compat/babyjub-cairo-input.mjs';
import { poseidonHash } from '../src/compat/poseidon.mjs';
import { requireZkKitPackage } from '../src/compat/zk-kit-require.mjs';

const { Base8, mulPointEscalar } = requireZkKitPackage('@zk-kit/baby-jubjub');
const { derivePublicKey, signMessage, verifySignature } = requireZkKitPackage('@zk-kit/eddsa-poseidon');

test('BabyJubJub scalar multiplication matches the existing zk-kit implementation', () => {
  for (const scalar of [0n, 1n, 2n, 5n, 17n, 253n]) {
    assert.deepEqual(
      babyjubScalarMul(BABYJUB_BASE8, scalar),
      mulPointEscalar(Base8, scalar).map(BigInt),
    );
  }
});

test('builds and verifies a BabyJubJub ECDH scalar multiplication transcript', () => {
  const witness = buildEcdhSharedKeyWitness(5n, BABYJUB_BASE8);
  const verified = verifyBabyjubScalarMulTranscript(witness);

  assert.equal(witness.steps.length, BABYJUB_SCALAR_BITS);
  assert.deepEqual(verified, mulPointEscalar(Base8, 5n).map(BigInt));
});

test('serializes Cairo executable arguments for ECDH transcript verification', () => {
  const cairoInput = buildCairoEcdhSharedKeyInput({
    privKey: '5',
    pubKey: BABYJUB_BASE8.map((value) => value.toString()),
  });
  const args = serializeCairoBabyjubScalarMulExecutableArgs(cairoInput);

  assert.equal(args.length, 11 + BABYJUB_SCALAR_BITS * 14);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.deepEqual(cairoInput.expected, mulPointEscalar(Base8, 5n).map(BigInt));
});

test('BabyJubJub Poseidon signature witness matches zk-kit verification', () => {
  const secretKey = Buffer.from([1, 2, 3, 4, 5]);
  const preimage = [123n, 456n, 789n];
  const message = poseidonSignatureMessage(preimage);
  const signature = signMessage(secretKey, message);
  const pubKey = derivePublicKey(secretKey).map(BigInt);
  const witness = buildBabyjubPoseidonSignatureWitness({
    pubKey,
    r8: signature.R8,
    s: signature.S,
    preimage,
  });

  assert.equal(message, poseidonHash(preimage));
  assert.equal(verifySignature(message, signature, pubKey), true);
  assert.equal(verifyBabyjubPoseidonSignatureWitness(witness), 1n);
});

test('BabyJubJub Poseidon signature witness returns invalid for a wrong preimage', () => {
  const secretKey = Buffer.from([9, 8, 7, 6, 5]);
  const preimage = [1001n, 1002n, 1003n];
  const message = poseidonSignatureMessage(preimage);
  const signature = signMessage(secretKey, message);
  const pubKey = derivePublicKey(secretKey).map(BigInt);
  const witness = buildBabyjubPoseidonSignatureWitness({
    pubKey,
    r8: signature.R8,
    s: signature.S,
    preimage: [1001n, 1002n, 1004n],
  });

  assert.equal(verifySignature(message, signature, pubKey), true);
  assert.equal(verifyBabyjubPoseidonSignatureWitness(witness), 0n);
});

test('serializes Cairo executable arguments for Poseidon signature verification', () => {
  const secretKey = Buffer.from([5, 4, 3, 2, 1]);
  const preimage = [77n, 88n, 99n];
  const message = poseidonSignatureMessage(preimage);
  const signature = signMessage(secretKey, message);
  const pubKey = derivePublicKey(secretKey).map(BigInt);
  const cairoInput = buildCairoBabyjubPoseidonSignatureInput({
    pubKey,
    r8: signature.R8,
    s: signature.S,
    preimage,
  });
  const args = serializeCairoBabyjubPoseidonSignatureExecutableArgs(cairoInput);

  assert.equal(cairoInput.valid, 1n);
  assert.equal(args.length, 7152);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
});
