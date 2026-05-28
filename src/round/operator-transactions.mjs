import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { decimalize } from '../encoding.mjs';

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function shellQuote(value) {
  const text = String(value);
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(text)) {
    return text;
  }
  return `'${text.replaceAll("'", "'\\''")}'`;
}

function scriptFromTransactions(manifest) {
  const lines = [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    '',
    `# ${manifest.role} transactions for ${manifest.contract}`,
    `# Flow: ${manifest.flow.join(' -> ')}`,
    '',
  ];
  for (const tx of manifest.transactions) {
    lines.push(`# ${tx.order}. ${tx.stage}: ${tx.description}`);
    if (tx.command && tx.status === 'ready') {
      lines.push(tx.command);
    } else if (tx.command) {
      lines.push('# template command; replace <WRAPPER_ADDRESS> before running');
      lines.push(`# ${tx.command}`);
    } else if (tx.requiredWrapperCallPath) {
      lines.push(`# requires Atlantic wrapper call: ${tx.requiredWrapperCallPath}`);
      lines.push(`# jq -r .submit.command ${shellQuote(tx.requiredWrapperCallPath)} | bash`);
    } else {
      lines.push(`# command unavailable: ${tx.status}`);
    }
    lines.push('');
  }
  return `${lines.join('\n')}\n`;
}

function wrapperTransaction({ order, stage, description, wrapperCall, wrapperCallPath, data, requires }) {
  const command = wrapperCall?.submit?.command;
  return {
    order,
    stage,
    actor: 'operator',
    contractFunction: wrapperCall?.submit?.function ?? {
      processDeactivate: 'submit_process_deactivate_atlantic_metadata_fact',
      processMessages: 'submit_process_messages_atlantic_metadata_fact',
      tally: 'submit_tally_atlantic_metadata_fact',
    }[stage],
    status: command ? 'ready' : 'requires_atlantic_wrapper_call',
    description,
    command,
    requiredWrapperCallPath: command ? undefined : wrapperCallPath,
    requires,
    data,
  };
}

export function loadOperatorRoundInputsFromDir(fixtureDir) {
  const root = resolve(fixtureDir);
  return {
    chain: readJson(resolve(root, 'chain.json')),
    processDeactivate: readJson(resolve(root, 'process-deactivate-stage-native.json')),
    processMessages: readJson(resolve(root, 'process-messages-stage-native.json')),
    tally: readJson(resolve(root, 'tally-native.json')),
    source: {
      fixtureDir: root,
      chain: resolve(root, 'chain.json'),
      processDeactivate: resolve(root, 'process-deactivate-stage-native.json'),
      processMessages: resolve(root, 'process-messages-stage-native.json'),
      tally: resolve(root, 'tally-native.json'),
    },
  };
}

export function buildOperatorRoundTransactions({
  fixture,
  wrapperAddress = '<WRAPPER_ADDRESS>',
  profile,
  wrapperCalls = {},
  wrapperCallPaths = {},
}) {
  const chain = fixture.chain;
  const processDeactivate = fixture.processDeactivate;
  const processMessages = fixture.processMessages;
  const tally = fixture.tally;
  if (!chain || !processDeactivate || !processMessages || !tally) {
    throw new Error('chain, processDeactivate, processMessages, and tally fixtures are required');
  }

  const transactions = [
    wrapperTransaction({
      order: 1,
      stage: 'processDeactivate',
      wrapperCall: wrapperCalls.processDeactivate,
      wrapperCallPath: wrapperCallPaths.processDeactivate,
      description: 'batch-process published deactivate messages and commit the deactivate tree root',
      requires: [
        'all voter publish_deactivate_message transactions for the batch are on-chain',
        'Atlantic processDeactivate proof is verified and registered',
      ],
      data: {
        currentDeactivateCommitment: decimalize(processDeactivate.currentDeactivateCommitment),
        newDeactivateCommitment: decimalize(processDeactivate.newDeactivateCommitment),
        currentStateCommitment: decimalize(chain.signup.initialStateCommitment),
        newDeactivateRoot: decimalize(processDeactivate.newDeactivateRoot),
        batchStartHash: decimalize(processDeactivate.batchStartHash),
        batchEndHash: decimalize(processDeactivate.batchEndHash),
      },
    }),
    wrapperTransaction({
      order: 2,
      stage: 'processMessages',
      wrapperCall: wrapperCalls.processMessages,
      wrapperCallPath: wrapperCallPaths.processMessages,
      description: 'batch-process encrypted vote messages into the new state commitment',
      requires: [
        'voter addNewKey proof has been accepted',
        'all voter publish_message transactions for the batch are on-chain',
        'Atlantic processMessages proof is verified and registered',
      ],
      data: {
        currentStateCommitment: decimalize(processMessages.currentStateCommitment),
        newStateCommitment: decimalize(processMessages.newStateCommitment),
        deactivateCommitment: decimalize(processMessages.deactivateCommitment),
        batchStartHash: decimalize(processMessages.batchStartHash),
        batchEndHash: decimalize(processMessages.batchEndHash),
      },
    }),
    wrapperTransaction({
      order: 3,
      stage: 'tally',
      wrapperCall: wrapperCalls.tally,
      wrapperCallPath: wrapperCallPaths.tally,
      description: 'prove the tally result commitment from the final state tree',
      requires: [
        'all vote messages are processed',
        'Atlantic tally proof is verified and registered',
      ],
      data: {
        stateCommitment: decimalize(tally.stateCommitment),
        currentTallyCommitment: decimalize(tally.currentTallyCommitment),
        newTallyCommitment: decimalize(tally.newTallyCommitment),
      },
    }),
  ];

  return {
    schema: 'zkstark-amaci.round-role-transactions.v1',
    role: 'operator',
    contract: 'MockAmaciRound',
    wrapperAddress,
    profile,
    flow: chain.flow,
    source: fixture.source,
    transactions,
  };
}

export function buildOperatorRoundTransactionsFromDir(options) {
  const fixture = loadOperatorRoundInputsFromDir(options.fixtureDir);
  return buildOperatorRoundTransactions({ ...options, fixture });
}

export function writeOperatorRoundTransactionFiles(manifest, { jsonPath, scriptPath }) {
  if (jsonPath) {
    writeJson(jsonPath, manifest);
  }
  if (scriptPath) {
    mkdirSync(dirname(scriptPath), { recursive: true });
    writeFileSync(scriptPath, scriptFromTransactions(manifest));
  }
  return { jsonPath, scriptPath };
}

export function operatorFixtureExists(fixtureDir) {
  const root = resolve(fixtureDir);
  return [
    'chain.json',
    'process-deactivate-stage-native.json',
    'process-messages-stage-native.json',
    'tally-native.json',
  ].every((file) => existsSync(resolve(root, file)));
}
