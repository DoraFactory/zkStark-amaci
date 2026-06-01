import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { evaluateAddNewKey } from '../add-new-key/add-new-key.mjs';
import { evaluateNativeProcessDeactivateMessagesBoundary } from '../deactivate/native-process-deactivate-messages.mjs';
import { evaluateNativeProcessMessagesBoundary } from '../msg/native-process-messages.mjs';
import { evaluateNativeTallyVotes } from '../tally/native-tally-votes.mjs';
import { decimalize, parseBigInt } from '../encoding.mjs';
import { MockIntegrityRegistry } from './tally-wrapper-model.mjs';
import { AmaciStateWrapperModel } from './amaci-wrapper-model.mjs';

export const DEFAULT_NATIVE_ROUND_PROGRAM_HASHES = Object.freeze({
  addNewKey: 0xadd0a11n,
  processDeactivate: 0xdea0a11n,
  processMessages: 0x1230a11n,
  tally: 0x7a110a11n,
});

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`failed to read ${label} at ${path}: ${error.message}`);
  }
}

export function loadNativeRoundFixtureDir(fixtureDir) {
  const dir = resolve(fixtureDir);
  return {
    addNewKey: readJson(resolve(dir, 'add-new-key-native.json'), 'add-new-key fixture'),
    processDeactivate: readJson(
      resolve(dir, 'process-deactivate-stage-native.json'),
      'process-deactivate fixture',
    ),
    processMessages: readJson(
      resolve(dir, 'process-messages-stage-native.json'),
      'process-messages fixture',
    ),
    tally: readJson(resolve(dir, 'tally-native.json'), 'tally fixture'),
    chain: readJson(resolve(dir, 'chain.json'), 'chain fixture'),
  };
}

function assertEqual(actual, expected, label) {
  if (parseBigInt(actual, `${label}.actual`) !== parseBigInt(expected, `${label}.expected`)) {
    throw new Error(
      `${label} mismatch: expected ${parseBigInt(expected, `${label}.expected`)}, got ${parseBigInt(actual, `${label}.actual`)}`,
    );
  }
}

function decimalSummary(value) {
  return value === undefined ? undefined : decimalize(value);
}

function acceptFact({ wrapper, integrity, circuit, fields, params, submit, registeredSecurityBits }) {
  const fact = wrapper.expectedFact(circuit, fields, params);
  integrity.registerFact(fact.factHash, registeredSecurityBits);
  const result = submit(fact);
  return {
    circuit,
    factHash: decimalize(fact.factHash),
    outputHash: decimalize(fact.outputHash),
    result: Object.fromEntries(
      Object.entries(result).map(([key, value]) => [key, decimalSummary(value)]),
    ),
  };
}

export function simulateNativeRoundWrapperFlow(fixture, options = {}) {
  const minSecurityBits = options.minSecurityBits ?? 96;
  const registeredSecurityBits = options.registeredSecurityBits ?? 128;
  const programHashes = options.programHashes ?? DEFAULT_NATIVE_ROUND_PROGRAM_HASHES;

  const addNewKey = evaluateAddNewKey(fixture.addNewKey);
  const processDeactivate = evaluateNativeProcessDeactivateMessagesBoundary(fixture.processDeactivate);
  const processMessages = evaluateNativeProcessMessagesBoundary(fixture.processMessages);
  const tally = evaluateNativeTallyVotes(fixture.tally);
  const chain = fixture.chain;

  assertEqual(
    addNewKey.publicFields.deactivateRootHash,
    processDeactivate.publicFields.newDeactivateRoot,
    'processDeactivate -> addNewKey deactivate root',
  );
  assertEqual(
    processDeactivate.publicFields.newDeactivateCommitment,
    processMessages.publicFields.deactivateCommitment,
    'deactivate -> processMessages commitment',
  );
  assertEqual(
    chain.addNewKey.newStateCommitment,
    processMessages.publicFields.currentStateCommitment,
    'addNewKey -> processMessages state commitment',
  );
  assertEqual(
    processMessages.publicFields.newStateCommitment,
    tally.publicFields.stateCommitment,
    'processMessages -> tally state commitment',
  );

  const initialStateCommitment = parseBigInt(
    chain.signup.initialStateCommitment,
    'chain.signup.initialStateCommitment',
  );
  const initialDeactivateCommitment = parseBigInt(
    processDeactivate.publicFields.currentDeactivateCommitment,
    'processDeactivate.currentDeactivateCommitment',
  );
  const initialTallyCommitment = parseBigInt(
    tally.publicFields.currentTallyCommitment,
    'tally.currentTallyCommitment',
  );

  const integrity = new MockIntegrityRegistry();
  const wrapper = new AmaciStateWrapperModel({
    integrity,
    programHashes,
    minSecurityBits,
      stateCommitment: initialStateCommitment,
    deactivateCommitment: initialDeactivateCommitment,
    currentTallyCommitment: initialTallyCommitment,
    strictLifecycle: true,
  });

  const lifecycle = [
    {
      stage: 'signup',
      actor: 'voter',
      contractAction: 'sign_up(pubKey, voiceCredits)',
      effect: 'initial StateTree leaf exists before deactivate',
    },
    {
      stage: 'deactivate',
      actor: 'voter',
      contractAction: 'publish_deactivate_message(encryptedCommand, encPubKey)',
      effect: 'deactivate message hash chain is extended',
    },
  ];
  const accepted = [];
  accepted.push(
    acceptFact({
      wrapper,
      integrity,
      circuit: 'processDeactivate',
      fields: {
        ...processDeactivate.publicFields,
        currentStateCommitment: initialStateCommitment,
      },
      params: processDeactivate.params,
      registeredSecurityBits,
      submit: (fact) =>
        wrapper.submitProcessDeactivate({
          fields: {
            ...processDeactivate.publicFields,
            currentStateCommitment: initialStateCommitment,
          },
          params: processDeactivate.params,
          factHash: fact.factHash,
        }),
    }),
  );
  lifecycle.push({
    stage: 'processDeactivate',
    actor: 'operator',
    contractAction: 'submit_process_deactivate_atlantic_metadata_fact(...)',
    effect: 'deactivateRoot/deactivateCommitment advance from the published deactivate chain',
  });

  accepted.push(
    acceptFact({
      wrapper,
      integrity,
      circuit: 'addNewKey',
      fields: {
        ...addNewKey.publicFields,
        currentStateCommitment: initialStateCommitment,
        newStateCommitment: chain.addNewKey.newStateCommitment,
      },
      params: addNewKey.params,
      registeredSecurityBits,
      submit: (fact) =>
        wrapper.submitAddNewKey({
          fields: {
            ...addNewKey.publicFields,
            currentStateCommitment: initialStateCommitment,
            newStateCommitment: chain.addNewKey.newStateCommitment,
          },
          params: addNewKey.params,
          factHash: fact.factHash,
        }),
    }),
  );
  lifecycle.push(
    {
      stage: 'addNewKey',
      actor: 'voter',
      contractAction: 'submit_add_new_key_atlantic_metadata_fact(nullifier, newStateCommitment, ...)',
      effect: 'nullifier is consumed and the new voting key becomes the active StateTree leaf',
    },
    {
      stage: 'vote',
      actor: 'voter',
      contractAction: 'publish_message(encryptedCommand, encPubKey)',
      effect: 'vote message hash chain is extended after addNewKey',
    },
  );

  accepted.push(
    acceptFact({
      wrapper,
      integrity,
      circuit: 'processMessages',
      fields: processMessages.publicFields,
      params: processMessages.params,
      registeredSecurityBits,
      submit: (fact) =>
        wrapper.submitProcessMessages({
          fields: processMessages.publicFields,
          params: processMessages.params,
          factHash: fact.factHash,
        }),
    }),
  );
  lifecycle.push({
    stage: 'processMessages',
    actor: 'operator',
    contractAction: 'submit_process_messages_atlantic_metadata_fact(...)',
    effect: 'vote messages are applied to the new key state leaf',
  });

  accepted.push(
    acceptFact({
      wrapper,
      integrity,
      circuit: 'tally',
      fields: tally.publicFields,
      params: tally.params,
      registeredSecurityBits,
      submit: (fact) =>
        wrapper.submitTally({
          fields: tally.publicFields,
          params: tally.params,
          factHash: fact.factHash,
        }),
    }),
  );
  lifecycle.push({
    stage: 'tally',
    actor: 'operator',
    contractAction: 'submit_tally_atlantic_metadata_fact(...)',
    effect: 'final tally commitment is produced and can be opened with results',
  });

  assertEqual(wrapper.stateCommitment, chain.tally.stateCommitment, 'final wrapper state commitment');
  assertEqual(
    wrapper.deactivateCommitment,
    chain.deactivate.newDeactivateCommitment,
    'final wrapper deactivate commitment',
  );
  assertEqual(
    wrapper.currentTallyCommitment,
    chain.tally.newTallyCommitment,
    'final wrapper tally commitment',
  );

  return {
    schema: 'zkstark-amaci.native-round-wrapper-flow.v1',
    status: 'ok',
    minSecurityBits,
    registeredSecurityBits,
    programHashes: Object.fromEntries(
      Object.entries(programHashes).map(([key, value]) => [key, decimalize(value)]),
    ),
    accepted,
    lifecycle,
    finalState: {
      stateCommitment: decimalize(wrapper.stateCommitment),
      deactivateCommitment: decimalize(wrapper.deactivateCommitment),
      tallyCommitment: decimalize(wrapper.currentTallyCommitment),
      keysAdded: decimalize(wrapper.keysAdded),
      deactivateBatchesProcessed: decimalize(wrapper.deactivateBatchesProcessed),
      messageBatchesProcessed: decimalize(wrapper.messageBatchesProcessed),
    },
    links: {
      deactivateToProcessMessages:
        parseBigInt(processDeactivate.publicFields.newDeactivateCommitment, 'deactivateCommitment') ===
        parseBigInt(processMessages.publicFields.deactivateCommitment, 'processMessagesDeactivateCommitment'),
      processDeactivateToAddNewKey:
        parseBigInt(processDeactivate.publicFields.newDeactivateRoot, 'processDeactivateNewRoot') ===
        parseBigInt(addNewKey.publicFields.deactivateRootHash, 'addNewKeyDeactivateRoot'),
      addNewKeyToProcessMessages:
        parseBigInt(chain.addNewKey.newStateCommitment, 'addNewKeyNewState') ===
        parseBigInt(processMessages.publicFields.currentStateCommitment, 'processMessagesCurrentState'),
      processMessagesToTallyState:
        parseBigInt(processMessages.publicFields.newStateCommitment, 'processMessagesNewState') ===
        parseBigInt(tally.publicFields.stateCommitment, 'tallyStateCommitment'),
    },
  };
}

export function simulateNativeRoundWrapperFlowFromDir(fixtureDir, options = {}) {
  return simulateNativeRoundWrapperFlow(loadNativeRoundFixtureDir(fixtureDir), options);
}
