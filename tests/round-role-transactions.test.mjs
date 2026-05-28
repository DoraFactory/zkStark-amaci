import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSmallNativeLifecycleRoundFixture } from '../src/fixtures/small-amaci-fixtures.mjs';
import { buildVoterRoundTransactions } from '../src/round/voter-transactions.mjs';
import { buildOperatorRoundTransactions } from '../src/round/operator-transactions.mjs';

function lifecycleFixture() {
  const fixture = buildSmallNativeLifecycleRoundFixture();
  return {
    chain: fixture.chain,
    addNewKey: fixture.addNewKey,
    processDeactivate: fixture.processDeactivate,
    processMessages: fixture.processMessages,
    tally: fixture.tally,
  };
}

test('exports voter transactions in the standard AMACI lifecycle order', () => {
  const manifest = buildVoterRoundTransactions({
    fixture: lifecycleFixture(),
    wrapperAddress: '0xabc',
    profile: 'amaci_test',
    wrapperCalls: {
      addNewKey: {
        submit: {
          function: 'submit_add_new_key_atlantic_metadata_fact',
          command: 'sncast add-new-key',
        },
      },
    },
  });

  assert.deepEqual(manifest.flow, [
    'signup',
    'deactivate',
    'processDeactivate',
    'addNewKey',
    'vote',
    'processMessages',
    'tally',
  ]);
  assert.deepEqual(
    manifest.transactions.map((tx) => tx.stage),
    [
      'signup',
      'signup',
      'signup',
      'deactivate',
      'deactivate',
      'deactivate',
      'addNewKey',
      'vote',
      'vote',
      'vote',
    ],
  );

  const signup = manifest.transactions[0];
  assert.equal(signup.contractFunction, 'sign_up');
  assert.match(signup.command, /--function sign_up/);
  assert.match(signup.command, /--profile amaci_test/);

  const deactivate = manifest.transactions.find((tx) => tx.stage === 'deactivate');
  assert.equal(deactivate.contractFunction, 'publish_deactivate_message');
  assert.equal(deactivate.calldata.length, 13);
  assert.equal(deactivate.calldata[0], '10');

  const addNewKey = manifest.transactions.find((tx) => tx.stage === 'addNewKey');
  assert.equal(addNewKey.status, 'ready');
  assert.equal(addNewKey.command, 'sncast add-new-key');

  const vote = manifest.transactions.find((tx) => tx.stage === 'vote');
  assert.equal(vote.contractFunction, 'publish_message');
  assert.equal(vote.calldata.length, 13);
});

test('exports operator proof-submit transactions in processDeactivate -> processMessages -> tally order', () => {
  const fixture = lifecycleFixture();
  const manifest = buildOperatorRoundTransactions({
    fixture,
    wrapperAddress: '0xabc',
    wrapperCalls: {
      processDeactivate: {
        submit: {
          function: 'submit_process_deactivate_atlantic_metadata_fact',
          command: 'sncast process-deactivate',
        },
      },
      processMessages: {
        submit: {
          function: 'submit_process_messages_atlantic_metadata_fact',
          command: 'sncast process-messages',
        },
      },
      tally: {
        submit: {
          function: 'submit_tally_atlantic_metadata_fact',
          command: 'sncast tally',
        },
      },
    },
  });

  assert.deepEqual(
    manifest.transactions.map((tx) => tx.stage),
    ['processDeactivate', 'processMessages', 'tally'],
  );
  assert.deepEqual(
    manifest.transactions.map((tx) => tx.status),
    ['ready', 'ready', 'ready'],
  );
  assert.equal(manifest.transactions[0].command, 'sncast process-deactivate');
  assert.equal(
    manifest.transactions[1].data.currentStateCommitment,
    fixture.chain.processMessages.currentStateCommitment,
  );
  assert.equal(manifest.transactions[2].contractFunction, 'submit_tally_atlantic_metadata_fact');
});

test('marks proof submits as requiring Atlantic wrapper calls when metadata is not fetched yet', () => {
  const manifest = buildOperatorRoundTransactions({
    fixture: lifecycleFixture(),
    wrapperCallPaths: {
      processDeactivate: '/tmp/process-deactivate-wrapper-call.json',
      processMessages: '/tmp/process-messages-wrapper-call.json',
      tally: '/tmp/tally-wrapper-call.json',
    },
  });

  assert.deepEqual(
    manifest.transactions.map((tx) => tx.status),
    [
      'requires_atlantic_wrapper_call',
      'requires_atlantic_wrapper_call',
      'requires_atlantic_wrapper_call',
    ],
  );
  assert.equal(
    manifest.transactions[0].requiredWrapperCallPath,
    '/tmp/process-deactivate-wrapper-call.json',
  );
});
