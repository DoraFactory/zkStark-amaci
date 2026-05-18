import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSmallNativeRoundFixture } from '../src/fixtures/small-amaci-fixtures.mjs';
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
