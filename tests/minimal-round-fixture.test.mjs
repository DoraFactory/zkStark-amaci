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
import { starkVerifyCommandSignature } from '../src/stark-native-crypto.mjs';

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

  assert.equal(fixture.chain.params.signupCount, 3);
  assert.equal(fixture.chain.params.newKeyStateIndex, 3);
  assert.equal(fixture.chain.params.messageBatchSize, 3);
  assert.deepEqual(fixture.chain.flow, [
    'signup',
    'deactivate',
    'processDeactivate',
    'addNewKey',
    'vote',
    'processMessages',
    'tally',
  ]);
  assert.equal(fixture.addNewKey.deactivateRoot, deactivate.publicFields.newDeactivateRoot.toString());
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

test('lifecycle vote commands are signed by the current rotating MACI key', () => {
  const fixture = buildSmallNativeLifecycleRoundFixture();

  for (const [index, witness] of fixture.processMessages.processOneWitnesses.entries()) {
    const signatureValid = starkVerifyCommandSignature(
      [witness.stateLeaf[0], witness.stateLeaf[1]],
      { rPoint: witness.cmdSigR8, s: witness.cmdSigS },
      witness.packedCommand,
      witness.cmdSalt,
    );
    assert.equal(
      signatureValid.toString(),
      witness.isSignatureValid,
      `message ${index} signature validity should match witness`,
    );
  }
});
