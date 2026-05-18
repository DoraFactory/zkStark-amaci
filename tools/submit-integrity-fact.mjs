#!/usr/bin/env node
import { resolve } from 'node:path';
import { submitIntegritySplitProof } from '../src/integrity/submission.mjs';

function usage() {
  return `Usage:
  node tools/submit-integrity-fact.mjs --split-calldata <path> [options]

Options:
  --split-calldata <path>       Split calldata package JSON or split calldata directory.
  --network <sepolia|mainnet>   Default: sepolia.
  --fact-registry <address>     Override FactRegistry address.
  --job-id <felt>               Split verifier job id. Default: current timestamp.
  --sncast <path>               sncast binary. Default: sncast.
  --send                        Actually submit transactions. Omitted means dry run.
  --out <path>                  Output submission JSON.
  --fact-hash <felt>            Expected registered fact hash to record.
  --verification-hash <felt>    Expected verification hash to record.
  --program-hash <felt>         Program hash to record.
  --verifier-config-hash <felt> Verifier config hash to record.
  --security-bits <n>           Security bits to record.
  --text                        Print compact status.

Examples:
  node tools/submit-integrity-fact.mjs \\
    --split-calldata /proofs/integrity-split-calldata.json \\
    --network sepolia \\
    --job-id 202605161 \\
    --out /proofs/integrity-submission.json \\
    --text

  node tools/submit-integrity-fact.mjs \\
    --split-calldata /proofs/integrity-split-calldata.json \\
    --network sepolia \\
    --job-id 202605161 \\
    --send \\
    --out /proofs/integrity-submission.json \\
    --text
`;
}

function parseArgs(argv) {
  const args = {
    splitCalldata: undefined,
    network: 'sepolia',
    factRegistry: undefined,
    jobId: undefined,
    sncast: 'sncast',
    send: false,
    out: undefined,
    text: false,
    expectedFact: {},
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--split-calldata') {
      args.splitCalldata = argv[++i];
    } else if (arg === '--network') {
      args.network = argv[++i];
    } else if (arg === '--fact-registry') {
      args.factRegistry = argv[++i];
    } else if (arg === '--job-id') {
      args.jobId = argv[++i];
    } else if (arg === '--sncast') {
      args.sncast = argv[++i];
    } else if (arg === '--send') {
      args.send = true;
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--fact-hash') {
      args.expectedFact.factHash = argv[++i];
    } else if (arg === '--verification-hash') {
      args.expectedFact.verificationHash = argv[++i];
    } else if (arg === '--program-hash') {
      args.expectedFact.programHash = argv[++i];
    } else if (arg === '--verifier-config-hash') {
      args.expectedFact.verifierConfigHash = argv[++i];
    } else if (arg === '--security-bits') {
      args.expectedFact.securityBits = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.splitCalldata) {
    throw new Error(`missing --split-calldata\n\n${usage()}`);
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const result = submitIntegritySplitProof({
  splitCalldata: resolve(args.splitCalldata),
  network: args.network,
  factRegistry: args.factRegistry,
  jobId: args.jobId,
  sncast: args.sncast,
  send: args.send,
  out: args.out ? resolve(args.out) : undefined,
  expectedFact: Object.keys(args.expectedFact).length > 0 ? args.expectedFact : undefined,
});

if (args.text) {
  process.stdout.write(
    [
      `Status: ${result.status}`,
      `Network: ${result.plan.network}`,
      `FactRegistry: ${result.plan.factRegistry}`,
      `Job ID: ${result.plan.jobId}`,
      `Transactions: ${result.plan.transactionCount}`,
      `First function: ${result.plan.transactions[0]?.functionName ?? 'none'}`,
      `Final function: ${result.plan.transactions.at(-1)?.functionName ?? 'none'}`,
      args.out ? `Submission JSON: ${resolve(args.out)}` : undefined,
    ]
      .filter(Boolean)
      .join('\n') + '\n',
  );
} else {
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
