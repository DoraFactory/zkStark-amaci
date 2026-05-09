import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  joinU128Pair,
  processMessagesInputHash,
} from '../src/compat/encoding.mjs';
import { hashLeftRight } from '../src/compat/poseidon.mjs';
import {
  buildCairoProcessMessagesInput,
  serializeCairoProcessMessagesExecutableArgs,
} from '../src/msg/cairo-input.mjs';
import {
  evaluateProcessMessages,
  packProcessMessagesVals,
  processMessageHashChain,
  unpackProcessMessagesPackedVals,
} from '../src/msg/process-messages.mjs';

function decimalize(value) {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map(decimalize);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, decimalize(val)]));
  }
  return value;
}

function buildFixture() {
  const packedVals = packProcessMessagesVals({
    isQuadraticCost: 1n,
    numSignUps: 15n,
    maxVoteOptions: 5n,
  });
  const coordPubKey = [11n, 22n];
  const coordPubKeyHash = hashLeftRight(coordPubKey[0], coordPubKey[1]);
  const msgs = [
    [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n],
    [11n, 12n, 13n, 14n, 15n, 16n, 17n, 18n, 19n, 20n],
    [21n, 22n, 23n, 24n, 25n, 26n, 27n, 28n, 29n, 30n],
    [31n, 32n, 33n, 34n, 35n, 36n, 37n, 38n, 39n, 40n],
    [41n, 42n, 43n, 44n, 45n, 46n, 47n, 48n, 49n, 50n],
  ];
  const encPubKeys = [
    [101n, 102n],
    [201n, 202n],
    [0n, 302n],
    [0n, 402n],
    [0n, 502n],
  ];
  const batchStartHash = 123n;
  const { endHash: batchEndHash } = processMessageHashChain(msgs, encPubKeys, batchStartHash);
  const currentStateRoot = 701n;
  const currentStateSalt = 702n;
  const currentStateCommitment = hashLeftRight(currentStateRoot, currentStateSalt);
  const newStateRoot = 801n;
  const newStateSalt = 802n;
  const newStateCommitment = hashLeftRight(newStateRoot, newStateSalt);
  const activeStateRoot = 901n;
  const deactivateRoot = 902n;
  const deactivateCommitment = hashLeftRight(activeStateRoot, deactivateRoot);
  const expectedPollId = 77n;
  const inputHash = processMessagesInputHash(
    packedVals,
    coordPubKeyHash,
    batchStartHash,
    batchEndHash,
    currentStateCommitment,
    newStateCommitment,
    deactivateCommitment,
    expectedPollId,
  );

  return decimalize({
    packedVals,
    inputHash,
    coordPubKey,
    batchStartHash,
    batchEndHash,
    currentStateRoot,
    currentStateSalt,
    currentStateCommitment,
    newStateRoot,
    newStateSalt,
    newStateCommitment,
    activeStateRoot,
    deactivateRoot,
    deactivateCommitment,
    expectedPollId,
    msgs,
    encPubKeys,
  });
}

test('validates the ProcessMessages public boundary and message hash chain', () => {
  const input = buildFixture();
  const result = evaluateProcessMessages(input);

  assert.deepEqual(unpackProcessMessagesPackedVals(input.packedVals), {
    isQuadraticCost: 1n,
    numSignUps: 15n,
    maxVoteOptions: 5n,
  });
  assert.equal(result.derived.inputHash.toString(), input.inputHash);
  assert.equal(result.derived.messageHashChain.length, 6);
  assert.equal(result.derived.messageHashChain[2], result.derived.messageHashChain[5]);
});

test('emits stable canonical ProcessMessages public output', () => {
  const input = buildFixture();
  const { publicFields, publicOutput } = evaluateProcessMessages(input);

  assert.equal(publicOutput.felts.length, 24);
  assert.equal(publicOutput.labels[0], 'magic');
  assert.equal(publicOutput.labels[2], 'circuit_id');
  assert.equal(publicOutput.labels.at(-1), 'input_hash_high128');

  assert.equal(
    joinU128Pair(publicOutput.felts[6], publicOutput.felts[7]).toString(),
    publicFields.packedVals.toString(),
  );
  assert.equal(
    joinU128Pair(publicOutput.felts[22], publicOutput.felts[23]).toString(),
    publicFields.inputHash.toString(),
  );
});

test('builds Cairo executable arguments for ProcessMessages boundary', () => {
  const input = buildFixture();
  const evaluated = evaluateProcessMessages(input);
  const cairoInput = buildCairoProcessMessagesInput(input, evaluated);
  const args = serializeCairoProcessMessagesExecutableArgs(cairoInput);

  assert.equal(args.length, 384);
  assert.equal(args[0], '0x10000000f00000005');
  assert.equal(args[1], '0x0');
  assert.equal(cairoInput.public_output.length, 24);
  assert.equal(
    cairoInput.program_input.witness.hashes.input_hash.out.low,
    cairoInput.program_input.fields.input_hash.low,
  );
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
});

test('rejects a tampered ProcessMessages batch end hash', () => {
  const input = buildFixture();
  input.batchEndHash = '1';
  const coordPubKeyHash = hashLeftRight(input.coordPubKey[0], input.coordPubKey[1]);
  input.inputHash = processMessagesInputHash(
    input.packedVals,
    coordPubKeyHash,
    input.batchStartHash,
    input.batchEndHash,
    input.currentStateCommitment,
    input.newStateCommitment,
    input.deactivateCommitment,
    input.expectedPollId,
  ).toString();

  assert.throws(() => evaluateProcessMessages(input), /batchEndHash mismatch/);
});

test('rejects out-of-range ProcessMessages packed values', () => {
  const input = buildFixture();
  input.packedVals = packProcessMessagesVals({
    isQuadraticCost: 1n,
    numSignUps: 15n,
    maxVoteOptions: 6n,
  }).toString();

  assert.throws(() => evaluateProcessMessages(input), /maxVoteOptions exceeds/);
});
