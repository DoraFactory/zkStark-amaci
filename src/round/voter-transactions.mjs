import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { decimalize } from '../encoding.mjs';

const DEFAULT_WRAPPER_ADDRESS = '<WRAPPER_ADDRESS>';

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

function normalizeCalldata(values) {
  return values.map((value) => decimalize(value));
}

function sncastInvokeCommand({ sncast = 'sncast', profile, contractAddress, functionName, calldata }) {
  return [
    sncast,
    profile ? `--profile ${profile}` : undefined,
    '--wait invoke',
    `--contract-address ${contractAddress}`,
    `--function ${functionName}`,
    `--calldata ${calldata.join(' ')}`,
  ]
    .filter(Boolean)
    .join(' ');
}

function messageCalldata(message, encPubKey, label) {
  if (!Array.isArray(message) || message.length !== 10) {
    throw new Error(`${label} message must contain exactly 10 felts`);
  }
  if (!Array.isArray(encPubKey) || encPubKey.length !== 2) {
    throw new Error(`${label} encPubKey must contain exactly 2 felts`);
  }
  return normalizeCalldata([message.length, ...message, ...encPubKey]);
}

function commandFromWrapperCall(wrapperCall, fallbackPath) {
  if (wrapperCall?.submit?.command) {
    return wrapperCall.submit.command;
  }
  if (fallbackPath) {
    return undefined;
  }
  return undefined;
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
      lines.push(`# template command; replace ${DEFAULT_WRAPPER_ADDRESS} before running`);
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

function uniqueSignupLeaves(processDeactivate) {
  const witnesses = processDeactivate?.processOneWitnesses;
  if (!Array.isArray(witnesses)) {
    throw new Error('processDeactivate.processOneWitnesses is required to export signup transactions');
  }
  const seen = new Set();
  const signups = [];
  for (const [index, witness] of witnesses.entries()) {
    const stateLeaf = witness.stateLeaf;
    if (!Array.isArray(stateLeaf) || stateLeaf.length < 3) {
      throw new Error(`processDeactivate.processOneWitnesses[${index}].stateLeaf is incomplete`);
    }
    const stateIndex = decimalize(witness.cmdStateIndex ?? index);
    if (seen.has(stateIndex)) {
      continue;
    }
    seen.add(stateIndex);
    signups.push({
      stateIndex,
      pubKey: normalizeCalldata([stateLeaf[0], stateLeaf[1]]),
      voiceCreditBalance: decimalize(stateLeaf[2]),
    });
  }
  return signups;
}

export function loadVoterRoundInputsFromDir(fixtureDir) {
  const root = resolve(fixtureDir);
  return {
    chain: readJson(resolve(root, 'chain.json')),
    addNewKey: readJson(resolve(root, 'add-new-key-native.json')),
    processDeactivate: readJson(resolve(root, 'process-deactivate-stage-native.json')),
    processMessages: readJson(resolve(root, 'process-messages-stage-native.json')),
    source: {
      fixtureDir: root,
      chain: resolve(root, 'chain.json'),
      addNewKey: resolve(root, 'add-new-key-native.json'),
      processDeactivate: resolve(root, 'process-deactivate-stage-native.json'),
      processMessages: resolve(root, 'process-messages-stage-native.json'),
    },
  };
}

export function buildVoterRoundTransactions({
  fixture,
  wrapperAddress = DEFAULT_WRAPPER_ADDRESS,
  profile,
  sncast = 'sncast',
  wrapperCalls = {},
  wrapperCallPaths = {},
}) {
  const chain = fixture.chain;
  const processDeactivate = fixture.processDeactivate;
  const processMessages = fixture.processMessages;
  const addNewKey = fixture.addNewKey;
  if (!chain || !processDeactivate || !processMessages || !addNewKey) {
    throw new Error('chain, addNewKey, processDeactivate, and processMessages fixtures are required');
  }

  const transactions = [];
  let order = 1;
  const contractAddress = wrapperAddress ?? DEFAULT_WRAPPER_ADDRESS;

  for (const signup of uniqueSignupLeaves(processDeactivate)) {
    const calldata = normalizeCalldata([
      signup.pubKey[0],
      signup.pubKey[1],
      signup.voiceCreditBalance,
    ]);
    transactions.push({
      order: order++,
      stage: 'signup',
      actor: 'voter',
      contractFunction: 'sign_up',
      status: contractAddress === DEFAULT_WRAPPER_ADDRESS ? 'template' : 'ready',
      description: `register old MACI public key at stateIndex ${signup.stateIndex}`,
      calldata,
      command: sncastInvokeCommand({
        sncast,
        profile,
        contractAddress,
        functionName: 'sign_up',
        calldata,
      }),
      data: signup,
    });
  }

  for (const [index, message] of processDeactivate.msgs.entries()) {
    const calldata = messageCalldata(
      message,
      processDeactivate.encPubKeys[index],
      `processDeactivate.msgs[${index}]`,
    );
    transactions.push({
      order: order++,
      stage: 'deactivate',
      actor: 'voter',
      contractFunction: 'publish_deactivate_message',
      status: contractAddress === DEFAULT_WRAPPER_ADDRESS ? 'template' : 'ready',
      description: `publish encrypted deactivate command ${index}`,
      calldata,
      command: sncastInvokeCommand({
        sncast,
        profile,
        contractAddress,
        functionName: 'publish_deactivate_message',
        calldata,
      }),
      data: {
        messageIndex: index,
        encPubKey: normalizeCalldata(processDeactivate.encPubKeys[index]),
      },
    });
  }

  const addNewKeyCommand = commandFromWrapperCall(
    wrapperCalls.addNewKey,
    wrapperCallPaths.addNewKey,
  );
  transactions.push({
    order: order++,
    stage: 'addNewKey',
    actor: 'voter',
    contractFunction: wrapperCalls.addNewKey?.submit?.function
      ?? 'submit_add_new_key_atlantic_metadata_fact',
    status: addNewKeyCommand ? 'ready' : 'requires_atlantic_wrapper_call',
    description: 'prove old deactivate credential and register the new MACI public key',
    calldata: wrapperCalls.addNewKey?.submit?.calldata,
    command: addNewKeyCommand,
    requiredWrapperCallPath: addNewKeyCommand ? undefined : wrapperCallPaths.addNewKey,
    requires: [
      'operator has accepted processDeactivate for all published deactivate messages',
      'addNewKey native output deactivateRoot equals the contract deactivate_root',
    ],
    data: {
      nullifier: decimalize(addNewKey.nullifier),
      newPubKey: normalizeCalldata(addNewKey.newPubKey),
      deactivateRoot: decimalize(addNewKey.deactivateRoot),
      newStateCommitment: decimalize(chain.addNewKey.newStateCommitment),
    },
  });

  for (const [index, message] of processMessages.msgs.entries()) {
    const calldata = messageCalldata(
      message,
      processMessages.encPubKeys[index],
      `processMessages.msgs[${index}]`,
    );
    transactions.push({
      order: order++,
      stage: 'vote',
      actor: 'voter',
      contractFunction: 'publish_message',
      status: contractAddress === DEFAULT_WRAPPER_ADDRESS ? 'template' : 'ready',
      description: `publish encrypted vote command ${index}`,
      calldata,
      command: sncastInvokeCommand({
        sncast,
        profile,
        contractAddress,
        functionName: 'publish_message',
        calldata,
      }),
      data: {
        messageIndex: index,
        encPubKey: normalizeCalldata(processMessages.encPubKeys[index]),
      },
    });
  }

  return {
    schema: 'zkstark-amaci.round-role-transactions.v1',
    role: 'voter',
    contract: 'MockAmaciRound',
    wrapperAddress: contractAddress,
    profile,
    flow: chain.flow,
    source: fixture.source,
    transactions,
  };
}

export function buildVoterRoundTransactionsFromDir(options) {
  const fixture = loadVoterRoundInputsFromDir(options.fixtureDir);
  return buildVoterRoundTransactions({ ...options, fixture });
}

export function writeVoterRoundTransactionFiles(manifest, { jsonPath, scriptPath }) {
  if (jsonPath) {
    writeJson(jsonPath, manifest);
  }
  if (scriptPath) {
    mkdirSync(dirname(scriptPath), { recursive: true });
    writeFileSync(scriptPath, scriptFromTransactions(manifest));
  }
  return { jsonPath, scriptPath };
}

export function voterFixtureExists(fixtureDir) {
  const root = resolve(fixtureDir);
  return [
    'chain.json',
    'add-new-key-native.json',
    'process-deactivate-stage-native.json',
    'process-messages-stage-native.json',
  ].every((file) => existsSync(resolve(root, file)));
}
