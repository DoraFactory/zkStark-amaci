import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { evaluateTallyVotes } from '../src/tally/tally-votes.mjs';
import {
  MockIntegrityRegistry,
  TallyVotesStarkWrapperModel,
} from '../src/wrapper/tally-wrapper-model.mjs';
import {
  calculateBootloadedFactHash,
  calculatePlainFactHash,
  calculateVerificationHash,
  isIntegrityHashingAvailable,
} from '../src/integrity/hashes.mjs';

const fixturePath = fileURLToPath(
  new URL(
    '../../amaci-operator/test-data/data/dora124w3vdmqtrjms9k4yhquqrd4r3qx5xww36ay5dg9wn8mnwe2e7dq5v8qfl/rust-inputgen/msg-tally/tally_inputs/000000.json',
    import.meta.url,
  ),
);

function loadFixture() {
  return JSON.parse(readFileSync(fixturePath, 'utf8'));
}

function setupPlainWrapper(securityBits = 96) {
  const input = loadFixture();
  const evaluated = evaluateTallyVotes(input);
  const integrity = new MockIntegrityRegistry();
  const tallyProgramHash = 0x1234n;
  const wrapper = new TallyVotesStarkWrapperModel({
    integrity,
    tallyProgramHash,
    minSecurityBits: securityBits,
    packedVals: evaluated.publicFields.packedVals,
    stateCommitment: evaluated.publicFields.stateCommitment,
    currentTallyCommitment: evaluated.publicFields.currentTallyCommitment,
  });
  const fact = calculatePlainFactHash(tallyProgramHash, evaluated.publicOutput.felts);
  return { input, evaluated, integrity, wrapper, fact };
}

test('wrapper model accepts a valid plain Integrity fact', { skip: !isIntegrityHashingAvailable() }, () => {
  const { input, integrity, wrapper, fact } = setupPlainWrapper();
  integrity.registerFact(fact.factHash, 128);

  const result = wrapper.submitTallyFact({
    newTallyCommitment: input.newTallyCommitment,
    inputHash: input.inputHash,
    factHash: fact.factHash,
  });

  assert.equal(result.currentTallyCommitment.toString(), input.newTallyCommitment);
  assert.equal(result.processedUserCount, 5n);
});

test('wrapper model rejects an unregistered fact', { skip: !isIntegrityHashingAvailable() }, () => {
  const { input, wrapper, fact } = setupPlainWrapper();

  assert.throws(
    () =>
      wrapper.submitTallyFact({
        newTallyCommitment: input.newTallyCommitment,
        inputHash: input.inputHash,
        factHash: fact.factHash,
      }),
    /INVALID_INTEGRITY_FACT/,
  );
});

test('wrapper model rejects insufficient security bits', { skip: !isIntegrityHashingAvailable() }, () => {
  const { input, integrity, wrapper, fact } = setupPlainWrapper(96);
  integrity.registerFact(fact.factHash, 80);

  assert.throws(
    () =>
      wrapper.submitTallyFact({
        newTallyCommitment: input.newTallyCommitment,
        inputHash: input.inputHash,
        factHash: fact.factHash,
      }),
    /INVALID_INTEGRITY_FACT/,
  );
});

test('wrapper model rejects a fact bound to different public output', { skip: !isIntegrityHashingAvailable() }, () => {
  const { input, integrity, wrapper, fact } = setupPlainWrapper();
  integrity.registerFact(fact.factHash, 128);

  assert.throws(
    () =>
      wrapper.submitTallyFact({
        newTallyCommitment: BigInt(input.newTallyCommitment) + 1n,
        inputHash: input.inputHash,
        factHash: fact.factHash,
      }),
    /FACT_HASH_BINDING_MISMATCH/,
  );
});

test('wrapper model supports bootloaded fact binding and verification hash', { skip: !isIntegrityHashingAvailable() }, () => {
  const input = loadFixture();
  const evaluated = evaluateTallyVotes(input);
  const integrity = new MockIntegrityRegistry();
  const tallyProgramHash = 0x1234n;
  const bootloaderProgramHash = 0x5678n;
  const verifierConfigHash = 0x9abcn;
  const minSecurityBits = 96;
  const fact = calculateBootloadedFactHash(
    bootloaderProgramHash,
    tallyProgramHash,
    evaluated.publicOutput.felts,
  );
  const verificationHash = calculateVerificationHash(
    fact.factHash,
    verifierConfigHash,
    minSecurityBits,
  );
  integrity.registerFact(fact.factHash, minSecurityBits);

  const wrapper = new TallyVotesStarkWrapperModel({
    integrity,
    tallyProgramHash,
    bootloaderProgramHash,
    verifierConfigHash,
    minSecurityBits,
    packedVals: evaluated.publicFields.packedVals,
    stateCommitment: evaluated.publicFields.stateCommitment,
    currentTallyCommitment: evaluated.publicFields.currentTallyCommitment,
  });

  const result = wrapper.submitTallyFact({
    newTallyCommitment: input.newTallyCommitment,
    inputHash: input.inputHash,
    factHash: fact.factHash,
    verificationHash,
  });

  assert.equal(result.currentTallyCommitment.toString(), input.newTallyCommitment);
});
