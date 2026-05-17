import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { bigintToHex, parseBigInt } from '../compat/encoding.mjs';
import { asciiToFelt } from './hashes.mjs';
import { loadSplitCalldataPackage } from './split-calldata.mjs';

const FACT_REGISTRY = Object.freeze({
  sepolia: '0x4ce7851f00b6c3289674841fd7a1b96b6fd41ed1edc248faccd672c26371b8c',
  mainnet: '0xcc63a1e8e7824642b89fa6baf996b8ed21fa4707be90ef7605570ca8e4f00b',
});

function normalizeNetwork(network = 'sepolia') {
  if (!Object.hasOwn(FACT_REGISTRY, network)) {
    throw new Error(`unsupported network: ${network}`);
  }
  return network;
}

function felt(value, label) {
  return bigintToHex(parseBigInt(value, label));
}

function calldataString(values) {
  return values.map(String).join(' ');
}

function sncastCommand({ sncast, contractAddress, functionName, calldata }) {
  return [
    sncast,
    '--wait',
    'invoke',
    '--contract-address',
    contractAddress,
    '--function',
    functionName,
    '--calldata',
    calldataString(calldata),
  ];
}

function runCommand(command) {
  const result = spawnSync(command[0], command.slice(1), {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 1024,
  });
  return {
    status: result.status,
    signal: result.signal,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

export function buildIntegritySubmissionPlan({
  splitCalldata,
  network,
  factRegistry,
  jobId,
  sncast = 'sncast',
  settings = {},
}) {
  const packageJson = loadSplitCalldataPackage(splitCalldata, settings);
  const normalizedNetwork = normalizeNetwork(network);
  const contractAddress = factRegistry ?? packageJson.contractAddress ?? FACT_REGISTRY[normalizedNetwork];
  const encoded = packageJson.settings?.encoded ?? {
    layout: bigintToHex(asciiToFelt(packageJson.settings.layout, 'layout')),
    hasher: bigintToHex(asciiToFelt(packageJson.settings.hasher, 'hasher')),
    stoneVersion: bigintToHex(asciiToFelt(packageJson.settings.stoneVersion, 'stoneVersion')),
    memoryVerification: bigintToHex(
      asciiToFelt(packageJson.settings.memoryVerification, 'memoryVerification'),
    ),
  };
  const normalizedJobId = felt(jobId ?? Date.now(), 'jobId');
  const transactions = [
    {
      label: 'initial',
      functionName: 'verify_proof_initial',
      calldata: [
        normalizedJobId,
        encoded.layout,
        encoded.hasher,
        encoded.stoneVersion,
        encoded.memoryVerification,
        ...packageJson.files.initial.calldata,
      ],
    },
    ...packageJson.files.steps.map((step) => ({
      label: step.name ?? `step${step.index}`,
      functionName: 'verify_proof_step',
      calldata: [normalizedJobId, ...step.calldata],
    })),
    {
      label: 'final',
      functionName: 'verify_proof_final_and_register_fact',
      calldata: [normalizedJobId, ...packageJson.files.final.calldata],
    },
  ];

  return {
    schema: 'zkstark-amaci.integrity-submission-plan.v1',
    network: normalizedNetwork,
    factRegistry: contractAddress,
    jobId: normalizedJobId,
    settings: packageJson.settings,
    splitCalldata: resolve(splitCalldata),
    transactionCount: transactions.length,
    transactions: transactions.map((tx) => ({
      ...tx,
      command: sncastCommand({
        sncast,
        contractAddress,
        functionName: tx.functionName,
        calldata: tx.calldata,
      }),
    })),
  };
}

export function submitIntegritySplitProof({
  splitCalldata,
  network = 'sepolia',
  factRegistry,
  jobId,
  sncast = 'sncast',
  send = false,
  out,
  expectedFact,
  settings,
}) {
  const plan = buildIntegritySubmissionPlan({
    splitCalldata,
    network,
    factRegistry,
    jobId,
    sncast,
    settings,
  });

  const result = {
    schema: 'zkstark-amaci.integrity-submission.v1',
    status: send ? 'submitted' : 'dry_run',
    plan,
    expectedFact,
    note: send
      ? 'Transactions were sent with sncast. Confirm the FactRegistered event and tx status on the selected network.'
      : 'Dry run only. Re-run with --send to submit transactions.',
    transactions: [],
  };

  if (send) {
    if (!existsSync(sncast) && !process.env.PATH?.split(':').some((dir) => existsSync(`${dir}/${sncast}`))) {
      throw new Error(`sncast not found: ${sncast}`);
    }
    for (const tx of plan.transactions) {
      const execution = runCommand(tx.command);
      result.transactions.push({
        label: tx.label,
        functionName: tx.functionName,
        command: tx.command,
        status: execution.status,
        signal: execution.signal,
        stdout: execution.stdout,
        stderr: execution.stderr,
      });
      if (execution.status !== 0) {
        result.status = 'failed';
        break;
      }
    }
  }

  if (out) {
    writeJson(resolve(out), result);
  }
  return result;
}

export { FACT_REGISTRY };
