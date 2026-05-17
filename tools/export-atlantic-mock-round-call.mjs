#!/usr/bin/env node
import { resolve } from 'node:path';
import { buildAtlanticMockRoundCallFromFiles } from '../src/atlantic/mock-round-call.mjs';

function usage() {
  return `Usage:
  node tools/export-atlantic-mock-round-call.mjs [options]

Options:
  --query-result <path>       atlantic-query-result.json from npm run atlantic:fetch-query.
  --summary <path>            final-query-summary.json. Used when --query-result is absent.
  --metadata <path>           Atlantic metadata.json artifact.
  --wrapper-address <addr>    Deployed MockAmaciRound address.
  --network <sepolia|mainnet> Default: sepolia.
  --fact-registry-mode <mode> satellite or direct. Default: satellite.
  --verifier-config-hash <f>  Default: 0.
  --security-bits <n>         Default: 50.
  --profile <name>            sncast profile for emitted commands.
  --sncast <path>             sncast binary. Default: sncast.
  --out <path>                Output JSON path.
  --text                      Print compact status.
  --help                      Show this help.
`;
}

function parseArgs(argv) {
  const args = {
    queryResultPath: undefined,
    summaryPath: undefined,
    metadataPath: undefined,
    wrapperAddress: undefined,
    network: 'sepolia',
    factRegistryMode: 'satellite',
    verifierConfigHash: 0,
    securityBits: 50,
    profile: undefined,
    sncast: 'sncast',
    out: undefined,
    text: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--query-result') {
      args.queryResultPath = argv[++i];
    } else if (arg === '--summary') {
      args.summaryPath = argv[++i];
    } else if (arg === '--metadata') {
      args.metadataPath = argv[++i];
    } else if (arg === '--wrapper-address') {
      args.wrapperAddress = argv[++i];
    } else if (arg === '--network') {
      args.network = argv[++i];
    } else if (arg === '--fact-registry-mode') {
      args.factRegistryMode = argv[++i];
    } else if (arg === '--verifier-config-hash') {
      args.verifierConfigHash = argv[++i];
    } else if (arg === '--security-bits') {
      args.securityBits = argv[++i];
    } else if (arg === '--profile') {
      args.profile = argv[++i];
    } else if (arg === '--sncast') {
      args.sncast = argv[++i];
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!args.queryResultPath && !args.summaryPath) {
    throw new Error(`missing --query-result or --summary\n\n${usage()}`);
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const result = buildAtlanticMockRoundCallFromFiles({
  ...args,
  queryResultPath: args.queryResultPath ? resolve(args.queryResultPath) : undefined,
  summaryPath: args.summaryPath ? resolve(args.summaryPath) : undefined,
  metadataPath: args.metadataPath ? resolve(args.metadataPath) : undefined,
  out: args.out ? resolve(args.out) : undefined,
});

if (args.text) {
  const lines = [
    `Atlantic query: ${result.query.id ?? 'unknown'}`,
    `Status: ${result.query.status}`,
    `Result: ${result.query.result}`,
    `Integrity fact hash: ${result.query.integrityFactHash}`,
    `FactRegistry mode: ${result.factRegistryMode}`,
    `FactRegistry address: ${result.factRegistryAddress}`,
    `Candidate matches: ${result.candidates.filter((c) => c.matchesIntegrityFact).length}`,
    result.selectedCandidate ? `Selected mode: ${result.selectedCandidate.label}` : undefined,
    result.submit.command ? `Submit command: ${result.submit.command}` : undefined,
    result.blockers.length ? `Blockers: ${result.blockers.join('; ')}` : undefined,
    result.warnings.length ? `Warnings: ${result.warnings.join('; ')}` : undefined,
    args.out ? `Output JSON: ${resolve(args.out)}` : undefined,
  ].filter(Boolean);
  process.stdout.write(`${lines.join('\n')}\n`);
} else {
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
