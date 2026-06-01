import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateAddNewKey } from '../src/add-new-key/add-new-key.mjs';
import {
  evaluateNativeProcessDeactivateMessagesBoundary,
} from '../src/deactivate/native-process-deactivate-messages.mjs';
import { buildFiveSignupSimplifiedRoundFixture } from '../src/fixtures/small-amaci-fixtures.mjs';
import { evaluateNativeProcessMessagesBoundary } from '../src/msg/native-process-messages.mjs';
import { evaluateNativeTallyVotes } from '../src/tally/native-tally-votes.mjs';
import { MockIntegrityRegistry } from '../src/wrapper/tally-wrapper-model.mjs';
import {
  AmaciStateWrapperModel,
} from '../src/wrapper/amaci-wrapper-model.mjs';
import {
  DEFAULT_NATIVE_ROUND_PROGRAM_HASHES,
} from '../src/wrapper/native-round-flow-model.mjs';

function registerAndSubmit({ wrapper, integrity, circuit, fields, params, submit }) {
  const fact = wrapper.expectedFact(circuit, fields, params);
  integrity.registerFact(fact.factHash, 128);
  return submit(fact);
}

test('five-signup simplified round links deactivate, addNewKey, two process batches, and two tally batches', () => {
  const fixture = buildFiveSignupSimplifiedRoundFixture();
  const addNewKey = evaluateAddNewKey(fixture.addNewKey);
  const processDeactivate = evaluateNativeProcessDeactivateMessagesBoundary(fixture.processDeactivate);
  const processMessages0 = evaluateNativeProcessMessagesBoundary(fixture.processMessages[0]);
  const processMessages1 = evaluateNativeProcessMessagesBoundary(fixture.processMessages[1]);
  const tally0 = evaluateNativeTallyVotes(fixture.tally[0]);
  const tally1 = evaluateNativeTallyVotes(fixture.tally[1]);

  assert.equal(fixture.chain.params.signupCount, 5);
  assert.equal(fixture.chain.params.deactivateMessageCount, 2);
  assert.equal(fixture.chain.params.addNewKeyCount, 1);
  assert.equal(fixture.chain.params.publishedVoteMessageCount, 5);
  assert.equal(fixture.chain.params.processMessageBatchSlots, 6);
  assert.equal(fixture.chain.params.invalidPaddingVoteSlots, 1);
  assert.equal(fixture.chain.params.processMessageBatches, 2);
  assert.equal(fixture.chain.params.tallyBatches, 2);
  assert.deepEqual(fixture.chain.votes.expectedRawResults, ['1', '0', '0', '0', '10']);
  assert.deepEqual(fixture.chain.flow, [
    'signup',
    'deactivate',
    'processDeactivate',
    'addNewKey',
    'vote',
    'processMessages[0]',
    'processMessages[1]',
    'tally[0]',
    'tally[1]',
  ]);

  assert.equal(addNewKey.publicFields.deactivateRootHash, processDeactivate.publicFields.newDeactivateRoot);
  assert.equal(processDeactivate.publicFields.newDeactivateCommitment, processMessages0.publicFields.deactivateCommitment);
  assert.equal(
    processMessages0.publicFields.newStateCommitment,
    processMessages1.publicFields.currentStateCommitment,
  );
  assert.equal(processMessages0.publicFields.batchEndHash, processMessages1.publicFields.batchStartHash);
  assert.equal(processMessages1.publicFields.newStateCommitment, tally0.publicFields.stateCommitment);
  assert.equal(tally0.publicFields.stateCommitment, tally1.publicFields.stateCommitment);
  assert.equal(tally0.publicFields.newTallyCommitment, tally1.publicFields.currentTallyCommitment);

  assert.deepEqual(
    tally1.derived.newResults.map((value) => value.toString()),
    [
      '1000000000000000000000001',
      '0',
      '0',
      '0',
      '10000000000000000000000050',
    ],
  );
  assert.deepEqual(Object.values(fixture.chain.links), Array.from({ length: 7 }, () => true));
});

test('five-signup simplified round is accepted by the strict mock wrapper in canonical order', () => {
  const fixture = buildFiveSignupSimplifiedRoundFixture();
  const addNewKey = evaluateAddNewKey(fixture.addNewKey);
  const processDeactivate = evaluateNativeProcessDeactivateMessagesBoundary(fixture.processDeactivate);
  const processMessages = fixture.processMessages.map((input) => evaluateNativeProcessMessagesBoundary(input));
  const tallies = fixture.tally.map((input) => evaluateNativeTallyVotes(input));

  const integrity = new MockIntegrityRegistry();
  const wrapper = new AmaciStateWrapperModel({
    integrity,
    programHashes: DEFAULT_NATIVE_ROUND_PROGRAM_HASHES,
    minSecurityBits: 96,
    stateCommitment: fixture.chain.signup.initialStateCommitment,
    deactivateCommitment: processDeactivate.publicFields.currentDeactivateCommitment,
    currentTallyCommitment: tallies[0].publicFields.currentTallyCommitment,
    strictLifecycle: true,
  });

  registerAndSubmit({
    wrapper,
    integrity,
    circuit: 'processDeactivate',
    fields: {
      ...processDeactivate.publicFields,
      currentStateCommitment: fixture.chain.signup.initialStateCommitment,
    },
    params: processDeactivate.params,
    submit: (fact) =>
      wrapper.submitProcessDeactivate({
        fields: {
          ...processDeactivate.publicFields,
          currentStateCommitment: fixture.chain.signup.initialStateCommitment,
        },
        params: processDeactivate.params,
        factHash: fact.factHash,
      }),
  });
  registerAndSubmit({
    wrapper,
    integrity,
    circuit: 'addNewKey',
    fields: {
      ...addNewKey.publicFields,
      currentStateCommitment: fixture.chain.signup.initialStateCommitment,
      newStateCommitment: fixture.chain.addNewKey.newStateCommitment,
    },
    params: addNewKey.params,
    submit: (fact) =>
      wrapper.submitAddNewKey({
        fields: {
          ...addNewKey.publicFields,
          currentStateCommitment: fixture.chain.signup.initialStateCommitment,
          newStateCommitment: fixture.chain.addNewKey.newStateCommitment,
        },
        params: addNewKey.params,
        factHash: fact.factHash,
      }),
  });
  for (const processMessagesBatch of processMessages) {
    registerAndSubmit({
      wrapper,
      integrity,
      circuit: 'processMessages',
      fields: processMessagesBatch.publicFields,
      params: processMessagesBatch.params,
      submit: (fact) =>
        wrapper.submitProcessMessages({
          fields: processMessagesBatch.publicFields,
          params: processMessagesBatch.params,
          factHash: fact.factHash,
        }),
    });
  }
  for (const tallyBatch of tallies) {
    registerAndSubmit({
      wrapper,
      integrity,
      circuit: 'tally',
      fields: tallyBatch.publicFields,
      params: tallyBatch.params,
      submit: (fact) =>
        wrapper.submitTally({
          fields: tallyBatch.publicFields,
          params: tallyBatch.params,
          factHash: fact.factHash,
        }),
    });
  }

  assert.equal(wrapper.keysAdded, 1n);
  assert.equal(wrapper.deactivateBatchesProcessed, 1n);
  assert.equal(wrapper.messageBatchesProcessed, 2n);
  assert.equal(wrapper.currentTallyCommitment, tallies[1].publicFields.newTallyCommitment);
  assert.equal(wrapper.stateCommitment, processMessages[1].publicFields.newStateCommitment);
  assert.equal(wrapper.deactivateCommitment, processDeactivate.publicFields.newDeactivateCommitment);
});
