import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import {
  buildNativeCairoTallyInput,
  serializeNativeCairoTallyExecutableArgs,
} from '../src/native-cairo-input.mjs';
import { STARK_FIELD } from '../src/constants.mjs';
import { evaluateNativeTallyVotes, unpackPackedVals } from '../src/tally/native-tally-votes.mjs';
import {
  calculatePlainFactHash,
  isIntegrityHashingAvailable,
} from '../src/integrity/hashes.mjs';

const fixturePath = fileURLToPath(
  new URL('../fixtures/tally-small/000000.json', import.meta.url),
);
const batch1FixturePath = fileURLToPath(
  new URL('../fixtures/tally-small/000001.json', import.meta.url),
);
const batch2FixturePath = fileURLToPath(
  new URL('../fixtures/tally-small/000002.json', import.meta.url),
);

const hasMainFixture = existsSync(fixturePath);
const hasAlternateFixtures = existsSync(batch1FixturePath) && existsSync(batch2FixturePath);
const mainFixtureSkip = hasMainFixture ? false : `missing AMACI fixture: ${fixturePath}`;
const alternateFixturesSkip = hasAlternateFixtures ? false : 'missing alternate AMACI tally fixtures';

function loadFixture(path = fixturePath) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

test('evaluates a Starknet-native tally fixture', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const result = evaluateNativeTallyVotes(input);

  assert.deepEqual(unpackPackedVals(input.packedVals), {
    numSignUps: 15n,
    batchNum: 0n,
  });
  assert.equal(result.publicOutput.felts.length, 12);
  assert.equal(result.publicOutput.labels[1], 'version');
  assert.equal(result.publicOutput.felts[1], 2n);
  assert.equal(result.publicOutput.labels[3], 'hash_scheme');
  assert.ok(result.publicOutput.felts.every((felt) => felt >= 0n && felt < STARK_FIELD));
});

test(
  'evaluates alternate Starknet-native tally batches',
  { skip: alternateFixturesSkip },
  () => {
    for (const path of [batch1FixturePath, batch2FixturePath]) {
      const input = loadFixture(path);
      const result = evaluateNativeTallyVotes(input);
      assert.equal(result.publicOutput.felts.length, 12);
      assert.ok(result.publicOutput.felts.every((felt) => felt >= 0n && felt < STARK_FIELD));
    }
  },
);

test('builds native Cairo executable arguments for tally', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const evaluated = evaluateNativeTallyVotes(input);
  const cairoInput = buildNativeCairoTallyInput(input, evaluated);
  const args = serializeNativeCairoTallyExecutableArgs(cairoInput);

  assert.equal(args.length, 95);
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
  assert.equal(cairoInput.public_output.length, 12);
  const expectedLeaf0VoteRoot = BigInt(input.stateLeaf[0][3]) === 0n
    ? '0'
    : evaluated.derived.voteRoots[0].toString();
  assert.equal(cairoInput.program_input.witness.state_leaf_0.v3, expectedLeaf0VoteRoot);
});

test('rejects malformed Starknet-native tally vote rows', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  input.votes[0].pop();

  assert.throws(() => evaluateNativeTallyVotes(input), /votes\[0\] must contain 5 values/);
});

test(
  'can calculate native Integrity-style tally fact hash when starknet.js is available',
  { skip: !hasMainFixture || !isIntegrityHashingAvailable() },
  () => {
    const input = loadFixture();
    const { publicOutput } = evaluateNativeTallyVotes(input);
    const hashes = calculatePlainFactHash(0x1234n, publicOutput.felts);

    assert.match(`0x${hashes.outputHash.toString(16)}`, /^0x[0-9a-f]+$/);
    assert.match(`0x${hashes.factHash.toString(16)}`, /^0x[0-9a-f]+$/);
  },
);
