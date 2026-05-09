import { existsSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { evaluateTallyVotes } from '../src/tally/tally-votes.mjs';
import {
  MockIntegrityRegistry,
  TallyVotesStarkWrapperModel,
} from '../src/wrapper/tally-wrapper-model.mjs';
import { AmaciStateWrapperModel } from '../src/wrapper/amaci-wrapper-model.mjs';
import {
  calculateBootloadedFactHash,
  calculatePlainFactHash,
  calculateVerificationHash,
  isIntegrityHashingAvailable,
} from '../src/integrity/hashes.mjs';

const fixturePath = fileURLToPath(
  new URL('../fixtures/tally-small/000000.json', import.meta.url),
);
const hasMainFixture = existsSync(fixturePath);
const wrapperTestSkip = !hasMainFixture || !isIntegrityHashingAvailable();

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

test('wrapper model accepts a valid plain Integrity fact', { skip: wrapperTestSkip }, () => {
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

test('wrapper model rejects an unregistered fact', { skip: wrapperTestSkip }, () => {
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

test('wrapper model rejects insufficient security bits', { skip: wrapperTestSkip }, () => {
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

test('wrapper model rejects a fact bound to different public output', { skip: wrapperTestSkip }, () => {
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

test('wrapper model supports bootloaded fact binding and verification hash', { skip: wrapperTestSkip }, () => {
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

test('generic AMACI wrapper model updates ProcessMessages state commitment', { skip: wrapperTestSkip }, () => {
  const integrity = new MockIntegrityRegistry();
  const wrapper = new AmaciStateWrapperModel({
    integrity,
    programHashes: { processMessages: 0x2222n },
    minSecurityBits: 96,
    stateCommitment: 100n,
    deactivateCommitment: 200n,
  });
  const fields = {
    packedVals: 1n,
    coordPubKeyHash: 2n,
    batchStartHash: 3n,
    batchEndHash: 4n,
    currentStateCommitment: 100n,
    newStateCommitment: 101n,
    deactivateCommitment: 200n,
    expectedPollId: 5n,
    inputHash: 6n,
  };
  const fact = wrapper.expectedFact('processMessages', fields);
  integrity.registerFact(fact.factHash, 128);

  const result = wrapper.submitProcessMessages({ fields, factHash: fact.factHash });

  assert.equal(result.stateCommitment, 101n);
  assert.equal(wrapper.stateCommitment, 101n);
});

test('generic AMACI wrapper model rejects stale ProcessMessages state', { skip: wrapperTestSkip }, () => {
  const integrity = new MockIntegrityRegistry();
  const wrapper = new AmaciStateWrapperModel({
    integrity,
    programHashes: { processMessages: 0x2222n },
    minSecurityBits: 96,
    stateCommitment: 100n,
    deactivateCommitment: 200n,
  });
  const fields = {
    packedVals: 1n,
    coordPubKeyHash: 2n,
    batchStartHash: 3n,
    batchEndHash: 4n,
    currentStateCommitment: 99n,
    newStateCommitment: 101n,
    deactivateCommitment: 200n,
    expectedPollId: 5n,
    inputHash: 6n,
  };
  const fact = wrapper.expectedFact('processMessages', fields);
  integrity.registerFact(fact.factHash, 128);

  assert.throws(
    () => wrapper.submitProcessMessages({ fields, factHash: fact.factHash }),
    /CURRENT_STATE_COMMITMENT_MISMATCH/,
  );
});

test('generic AMACI wrapper model tracks AddNewKey nullifiers', { skip: wrapperTestSkip }, () => {
  const integrity = new MockIntegrityRegistry();
  const wrapper = new AmaciStateWrapperModel({
    integrity,
    programHashes: { addNewKey: 0x3333n },
    minSecurityBits: 96,
  });
  const fields = {
    deactivateRoot: 1n,
    coordPubKeyHash: 2n,
    nullifier: 3n,
    d1: [4n, 5n],
    d2: [6n, 7n],
    newPubKeyHash: 8n,
    pollId: 9n,
    inputHash: 10n,
  };
  const fact = wrapper.expectedFact('addNewKey', fields);
  integrity.registerFact(fact.factHash, 128);

  wrapper.submitAddNewKey({ fields, factHash: fact.factHash });

  assert.throws(
    () => wrapper.submitAddNewKey({ fields, factHash: fact.factHash }),
    /NULLIFIER_ALREADY_USED/,
  );
});

test('generic AMACI wrapper model updates ProcessDeactivate commitment', { skip: wrapperTestSkip }, () => {
  const integrity = new MockIntegrityRegistry();
  const wrapper = new AmaciStateWrapperModel({
    integrity,
    programHashes: { processDeactivate: 0x4444n },
    minSecurityBits: 96,
    deactivateCommitment: 55n,
    currentStateRoot: 77n,
  });
  const fields = {
    newDeactivateRoot: 1n,
    coordPubKeyHash: 2n,
    batchStartHash: 3n,
    batchEndHash: 4n,
    currentDeactivateCommitment: 55n,
    newDeactivateCommitment: 56n,
    currentStateRoot: 77n,
    expectedPollId: 8n,
    inputHash: 9n,
  };
  const fact = wrapper.expectedFact('processDeactivate', fields);
  integrity.registerFact(fact.factHash, 128);

  const result = wrapper.submitProcessDeactivate({ fields, factHash: fact.factHash });

  assert.equal(result.deactivateCommitment, 56n);
});
