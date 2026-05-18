import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { joinU128Pair, tallyInputHash } from '../src/compat/encoding.mjs';
import { poseidonHashBn254 } from '../src/compat/poseidon-bn254.mjs';
import { hash10, hash13, isCircomPoseidonAvailable, poseidonHashFromCircom } from '../src/compat/poseidon.mjs';
import { buildCairoTallyInput, serializeCairoExecutableArgs } from '../src/cairo-input.mjs';
import {
  buildNativeCairoTallyInput,
  serializeNativeCairoTallyExecutableArgs,
} from '../src/native-cairo-input.mjs';
import { mutateSplitU256, runTallyCairoModel } from '../src/cairo-model/tally-program.mjs';
import { collectTallyHashVectors } from '../src/hash-vectors.mjs';
import { verifyHashVectors } from '../src/hash-vector-check.mjs';
import { STARK_FIELD } from '../src/constants.mjs';
import { evaluateNativeTallyVotes } from '../src/tally/native-tally-votes.mjs';
import { evaluateTallyVotes, unpackPackedVals } from '../src/tally/tally-votes.mjs';
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
const hasCircomPoseidon = isCircomPoseidonAvailable();
const mainFixtureSkip = hasMainFixture ? false : `missing AMACI fixture: ${fixturePath}`;
const alternateFixturesSkip = hasAlternateFixtures ? false : 'missing alternate AMACI tally fixtures';
const circomPoseidonSkip = hasCircomPoseidon ? false : 'circom package is not installed';
const nativePoseidonSkip = isIntegrityHashingAvailable() ? false : 'starknet.js hashing helpers are not installed';

function loadFixture(path = fixturePath) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

test('validates the existing AMACI TallyVotes fixture', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const result = evaluateTallyVotes(input);

  assert.equal(result.derived.inputHash.toString(), input.inputHash);
  assert.equal(result.derived.newTallyCommitment.toString(), input.newTallyCommitment);
  assert.deepEqual(unpackPackedVals(input.packedVals), {
    numSignUps: 15n,
    batchNum: 0n,
  });
});

test(
  'validates alternate existing AMACI TallyVotes batches without changing them',
  { skip: alternateFixturesSkip },
  () => {
    for (const path of [batch1FixturePath, batch2FixturePath]) {
      const input = loadFixture(path);
      const result = evaluateTallyVotes(input);
      assert.equal(result.derived.inputHash.toString(), input.inputHash);
      assert.equal(result.derived.newTallyCommitment.toString(), input.newTallyCommitment);
    }
  },
);

test('computes the contract-compatible inputHash', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const hash = tallyInputHash(
    BigInt(input.packedVals),
    BigInt(input.stateCommitment),
    BigInt(input.currentTallyCommitment),
    BigInt(input.newTallyCommitment),
  );

  assert.equal(hash.toString(), input.inputHash);
});

test('pure BN254 Poseidon matches the existing circom package', { skip: circomPoseidonSkip }, () => {
  const vectors = [
    [0n, 0n],
    [1n, 2n],
    [1234567890n, 987654321n],
    [0n, 6n, 4n, 0n, 0n],
    [1n, 2n, 3n, 4n, 5n],
  ];

  for (const inputs of vectors) {
    assert.equal(poseidonHashBn254(inputs).toString(), poseidonHashFromCircom(inputs).toString());
  }

  const hash10Input = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n];
  const first = poseidonHashFromCircom(hash10Input.slice(0, 5));
  const second = poseidonHashFromCircom(hash10Input.slice(5, 10));
  assert.equal(hash10(hash10Input).toString(), poseidonHashFromCircom([first, second]).toString());

  const hash13Input = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n, 13n];
  const hash13First = poseidonHashFromCircom(hash13Input.slice(0, 5));
  const hash13Second = poseidonHashFromCircom(hash13Input.slice(5, 10));
  assert.equal(
    hash13(hash13Input).toString(),
    poseidonHashFromCircom([hash13First, hash13Second, 11n, 12n, 13n]).toString(),
  );
});

test('emits stable canonical public output with split uint256 values', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const { publicOutput, publicFields } = evaluateTallyVotes(input);

  assert.equal(publicOutput.felts.length, 16);
  assert.equal(publicOutput.labels[0], 'magic');
  assert.equal(publicOutput.labels.at(-1), 'input_hash_high128');

  const packedLow = publicOutput.felts[6];
  const packedHigh = publicOutput.felts[7];
  assert.equal(joinU128Pair(packedLow, packedHigh).toString(), publicFields.packedVals.toString());

  const inputHashLow = publicOutput.felts[14];
  const inputHashHigh = publicOutput.felts[15];
  assert.equal(joinU128Pair(inputHashLow, inputHashHigh).toString(), publicFields.inputHash.toString());
});

test('builds fixed-size Cairo program input for the migrated tally relation', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const evaluated = evaluateTallyVotes(input);
  const cairoInput = buildCairoTallyInput(input, evaluated);

  assert.equal(
    joinU128Pair(
      cairoInput.program_input.witness.state_leaf_0.v3.low,
      cairoInput.program_input.witness.state_leaf_0.v3.high,
    ).toString(),
    input.stateLeaf[0][3],
  );
  assert.equal(
    joinU128Pair(
      cairoInput.program_input.witness.hashes.new_results_root.inputs.v1.low,
      cairoInput.program_input.witness.hashes.new_results_root.inputs.v1.high,
    ).toString(),
    evaluated.derived.newResults[1].toString(),
  );
  assert.equal(
    cairoInput.program_input.witness.hashes.new_tally_commitment.out.low,
    cairoInput.fields.new_tally_commitment.low,
  );
  assert.equal(
    cairoInput.program_input.witness.hashes.new_tally_commitment.out.high,
    cairoInput.fields.new_tally_commitment.high,
  );
  assert.equal(
    joinU128Pair(
      cairoInput.program_input.witness.hashes.state_root_from_path.inputs.v0.low,
      cairoInput.program_input.witness.hashes.state_root_from_path.inputs.v0.high,
    ).toString(),
    evaluated.derived.stateSubroot.toString(),
  );
  assert.equal(cairoInput.public_output.length, 16);
});

test('serializes Cairo executable arguments for scarb execute', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const evaluated = evaluateTallyVotes(input);
  const cairoInput = buildCairoTallyInput(input, evaluated);
  const args = serializeCairoExecutableArgs(cairoInput);

  assert.equal(args.length, 488);
  assert.equal(args[0], '0xf00000000');
  assert.equal(args[1], '0x0');
  assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
});

test(
  'evaluates a Starknet-native hash tally v2 fixture without BN254 hash claims',
  { skip: mainFixtureSkip || nativePoseidonSkip },
  () => {
    const input = loadFixture();
    const legacy = evaluateTallyVotes(input);
    const evaluated = evaluateNativeTallyVotes(input);
    const cairoInput = buildNativeCairoTallyInput(input, evaluated);
    const args = serializeNativeCairoTallyExecutableArgs(cairoInput);

    assert.equal(evaluated.publicOutput.felts.length, 12);
    assert.equal(evaluated.publicOutput.labels[1], 'version');
    assert.equal(evaluated.publicOutput.felts[1], 2n);
    assert.equal(evaluated.publicOutput.labels[3], 'hash_scheme');
    assert.notEqual(
      evaluated.publicFields.newTallyCommitment.toString(),
      legacy.publicFields.newTallyCommitment.toString(),
    );
    assert.ok(evaluated.publicOutput.felts.every((felt) => felt >= 0n && felt < STARK_FIELD));
    assert.equal(args.length, 95);
    assert.ok(args.every((value) => /^0x[0-9a-f]+$/.test(value)));
    assert.equal(cairoInput.public_output.length, 12);
    const expectedLeaf0VoteRoot = BigInt(input.stateLeaf[0][3]) === 0n
      ? '0'
      : evaluated.derived.voteRoots[0].toString();
    assert.equal(cairoInput.program_input.witness.state_leaf_0.v3, expectedLeaf0VoteRoot);
  },
);

test('cairo model accepts the generated tally program input', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const evaluated = evaluateTallyVotes(input);
  const cairoInput = buildCairoTallyInput(input, evaluated);
  const result = runTallyCairoModel(cairoInput.program_input);

  assert.deepEqual(result.publicOutput.decimalFelts, evaluated.publicOutput.decimalFelts);
  assert.deepEqual(
    result.derived.newResults.map((value) => value.toString()),
    evaluated.derived.newResults.map((value) => value.toString()),
  );
});

test('exports stable hash vectors for Cairo hash-gate implementation', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const evaluated = evaluateTallyVotes(input);
  const cairoInput = buildCairoTallyInput(input, evaluated);
  const vectors = collectTallyHashVectors(cairoInput.program_input);

  assert.equal(vectors.length, 19);
  assert.deepEqual(
    vectors.map((v) => v.type).reduce((counts, type) => ({ ...counts, [type]: (counts[type] ?? 0) + 1 }), {}),
    {
      poseidon2: 3,
      poseidon5: 10,
      poseidon10: 5,
      sha256_u256x4_mod_bn254: 1,
    },
  );
  assert.equal(vectors[0].id, 'state_commitment');
  assert.equal(vectors[0].inputs[0], input.stateRoot);
  assert.equal(vectors[0].output, input.stateCommitment);
  assert.equal(vectors.at(-1).id, 'new_tally_commitment');
  assert.equal(vectors.at(-1).output, input.newTallyCommitment);
  assert.equal(verifyHashVectors(vectors).length, vectors.length);
});

test('cairo model rejects a tampered hash-gate preimage', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const evaluated = evaluateTallyVotes(input);
  const cairoInput = buildCairoTallyInput(input, evaluated);
  const programInput = structuredClone(cairoInput.program_input);
  programInput.witness.hashes.new_tally_commitment.in1 = mutateSplitU256(
    programInput.witness.hashes.new_tally_commitment.in1,
  );

  assert.throws(() => runTallyCairoModel(programInput), /newTallyCommitment\.in1 mismatch/);
});

test('cairo model rejects a tampered hash-gate output', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const evaluated = evaluateTallyVotes(input);
  const cairoInput = buildCairoTallyInput(input, evaluated);
  const programInput = structuredClone(cairoInput.program_input);
  programInput.witness.hashes.state_commitment.out = mutateSplitU256(
    programInput.witness.hashes.state_commitment.out,
  );

  assert.throws(() => runTallyCairoModel(programInput), /stateCommitment mismatch/);
});

test('cairo model rejects a tampered packedVals witness', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  const evaluated = evaluateTallyVotes(input);
  const cairoInput = buildCairoTallyInput(input, evaluated);
  const programInput = structuredClone(cairoInput.program_input);
  programInput.witness.batch_num = mutateSplitU256(programInput.witness.batch_num);

  assert.throws(() => runTallyCairoModel(programInput), /packedVals mismatch/);
});

test('rejects a tampered new tally commitment', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  input.newTallyCommitment = '1';

  assert.throws(() => evaluateTallyVotes(input), /inputHash mismatch|newTallyCommitment mismatch/);
});

test('rejects tampered vote leaves', { skip: mainFixtureSkip }, () => {
  const input = loadFixture();
  input.votes[0][1] = (BigInt(input.votes[0][1]) + 1n).toString();

  assert.throws(() => evaluateTallyVotes(input), /vote option root/);
});

test(
  'can calculate Integrity-style fact hash when starknet.js is available',
  { skip: !hasMainFixture || !isIntegrityHashingAvailable() },
  () => {
    const input = loadFixture();
    const { publicOutput } = evaluateTallyVotes(input);
    const hashes = calculatePlainFactHash(0x1234n, publicOutput.felts);

    assert.match(`0x${hashes.outputHash.toString(16)}`, /^0x[0-9a-f]+$/);
    assert.match(`0x${hashes.factHash.toString(16)}`, /^0x[0-9a-f]+$/);
  },
);
