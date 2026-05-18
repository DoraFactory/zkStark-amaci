#!/usr/bin/env node
import { resolve } from 'node:path';
import { fetchAtlanticQueryResult } from '../src/atlantic/query-result.mjs';

function usage() {
  return `Usage:
  node tools/fetch-atlantic-query-result.mjs --query-id <id> --out-dir <dir> [options]

Options:
  --query-id <id>        Atlantic query id.
  --out-dir <dir>        Output directory.
  --download-artifacts   Download metadataUrls artifacts into <out-dir>/artifacts.
  --api-key <value>      Atlantic API key. Prefer --api-key-env.
  --api-key-env <name>   Environment variable containing the API key. Default: ATLANTIC_API_KEY.
  --text                 Print compact status.
  --help                 Show this help.
`;
}

function parseArgs(argv) {
  const args = {
    queryId: undefined,
    outDir: undefined,
    downloadArtifacts: false,
    apiKey: undefined,
    apiKeyEnv: 'ATLANTIC_API_KEY',
    text: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--query-id') {
      args.queryId = argv[++i];
    } else if (arg === '--out-dir') {
      args.outDir = argv[++i];
    } else if (arg === '--download-artifacts') {
      args.downloadArtifacts = true;
    } else if (arg === '--api-key') {
      args.apiKey = argv[++i];
    } else if (arg === '--api-key-env') {
      args.apiKeyEnv = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.queryId || !args.outDir) {
    throw new Error(`missing --query-id or --out-dir\n\n${usage()}`);
  }
  if (!args.apiKey && args.apiKeyEnv) {
    args.apiKey = process.env[args.apiKeyEnv];
  }
  return args;
}

function textReport(result) {
  const s = result.summary;
  const lines = [
    `Atlantic query: ${result.queryId}`,
    `Status: ${s.status}`,
    `Step: ${s.step}`,
    `Result: ${s.result}`,
    `Network: ${s.network}`,
    `Chain: ${s.chain}`,
    `Transaction ID: ${s.transactionId ?? 'none'}`,
    `Program hash: ${s.programHash ?? 'none'}`,
    `Integrity fact hash: ${s.integrityFactHash ?? 'none'}`,
    `Sharp fact hash: ${s.sharpFactHash ?? 'none'}`,
    `Mock fact: ${s.isFactMocked}`,
    `Mock proof: ${s.isProofMocked}`,
    `Created: ${s.createdAt ?? 'none'}`,
    `Completed: ${s.completedAt ?? 'none'}`,
    `Status JSON: ${result.statusPath}`,
    `Summary JSON: ${result.summaryPath}`,
    `Downloaded artifacts: ${result.artifacts.length}`,
  ];
  if (s.errorReason) {
    lines.push(`Error: ${s.errorReason}`);
  }
  return `${lines.join('\n')}\n`;
}

const args = parseArgs(process.argv.slice(2));
const result = await fetchAtlanticQueryResult(args.queryId, resolve(args.outDir), args);

if (args.text) {
  process.stdout.write(textReport(result));
} else {
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

