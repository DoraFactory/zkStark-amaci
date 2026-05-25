import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSmallNativeLifecycleRoundFixture } from '../src/fixtures/small-amaci-fixtures.mjs';
import { simulateNativeRoundWrapperFlow } from '../src/wrapper/native-round-flow-model.mjs';

test('native full round wrapper model accepts the 4-stage lifecycle in order', () => {
  const fixture = buildSmallNativeLifecycleRoundFixture();
  const result = simulateNativeRoundWrapperFlow(fixture);

  assert.equal(result.status, 'ok');
  assert.equal(result.accepted.map((entry) => entry.circuit).join(','), [
    'addNewKey',
    'processDeactivate',
    'processMessages',
    'tally',
  ].join(','));
  assert.equal(result.finalState.stateCommitment, fixture.chain.tally.stateCommitment);
  assert.equal(result.finalState.deactivateCommitment, fixture.chain.deactivate.newDeactivateCommitment);
  assert.equal(result.finalState.tallyCommitment, fixture.chain.tally.newTallyCommitment);
  assert.equal(result.finalState.keysAdded, '1');
  assert.equal(result.finalState.deactivateBatchesProcessed, '1');
  assert.equal(result.finalState.messageBatchesProcessed, '1');
});
