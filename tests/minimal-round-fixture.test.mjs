import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSmallNativeLifecycleRoundFixture,
  buildSmallNativeRoundFixture,
} from '../src/fixtures/small-amaci-fixtures.mjs';
import {
  evaluateNativeProcessDeactivateMessagesBoundary,
} from '../src/deactivate/native-process-deactivate-messages.mjs';
import { evaluateNativeProcessMessagesBoundary } from '../src/msg/native-process-messages.mjs';
import { evaluateNativeTallyVotes } from '../src/tally/native-tally-votes.mjs';

test('minimal native round fixture links process messages into tally', () => {
  const fixture = buildSmallNativeRoundFixture();
  const processMessages = evaluateNativeProcessMessagesBoundary(fixture.processMessages);
  const tally = evaluateNativeTallyVotes(fixture.tally);

  assert.equal(
    processMessages.publicFields.newStateCommitment,
    tally.publicFields.stateCommitment,
  );
  assert.equal(
    fixture.chain.processMessagesNewStateCommitment,
    fixture.chain.tallyStateCommitment,
  );
  assert.equal(fixture.chain.processMessagesToTallyStateMatches, true);
  assert.equal(tally.publicFields.currentTallyCommitment, 0n);
});

test('lifecycle native round fixture links deactivate, process messages, and tally', () => {
  const fixture = buildSmallNativeLifecycleRoundFixture();
  const deactivate = evaluateNativeProcessDeactivateMessagesBoundary(fixture.processDeactivate);
  const processMessages = evaluateNativeProcessMessagesBoundary(fixture.processMessages);
  const tally = evaluateNativeTallyVotes(fixture.tally);

  assert.equal(fixture.chain.params.signupCount, 1);
  assert.equal(fixture.chain.params.messageBatchSize, 3);
  assert.equal(
    deactivate.publicFields.newDeactivateCommitment,
    processMessages.publicFields.deactivateCommitment,
  );
  assert.equal(
    processMessages.publicFields.newStateCommitment,
    tally.publicFields.stateCommitment,
  );
  assert.equal(fixture.chain.links.deactivateToProcessMessages, true);
  assert.equal(fixture.chain.links.processMessagesToTallyState, true);
});
