#!/usr/bin/env node
import { resolve } from 'node:path';
import { createAtlanticQueryBundle } from '../src/atlantic/query-bundle.mjs';

function usage() {
  return `Usage:
  node tools/export-atlantic-query-bundle.mjs --stone-air-run <stone-air-run.json> --out-dir <dir> [options]

Options:
  --stone-air-run <path>      Stone AIR metadata from npm run stone:air:*
  --out-dir <dir>             Output directory for Atlantic-compatible files.
  --declared-job-size <size>  XS, S, M, or L. Default: S.
  --external-id <value>       Optional external tracking id.
  --dedup-id <value>          Optional Atlantic dedup id.
  --layout <layout>           Default: layout from stone-air-run.json.
  --sharp-prover <name>       stone or stwo. Default: stone.
  --result <result>           Default: PROOF_VERIFICATION_ON_L2.
  --network <network>         TESTNET or MAINNET. Default: TESTNET.
  --hints <hint>              Optional Atlantic hint, e.g. herodotus_sn_grower.
  --program-hash <felt>       Optional registered Atlantic program hash.
  --mock-fact-hash <bool>     false or true. Default: false.
  --text                      Print a compact report.
  --help                      Show this help.

The generated bundle contains:
  - programFile: Cairo1 Sierra JSON for Atlantic
  - inputFile: cairo1-run Rust VM text input
  - atlantic-query-bundle.json
  - submit-atlantic-query.sh
`;
}

function parseArgs(argv) {
  const args = {
    stoneAirRun: undefined,
    outDir: undefined,
    declaredJobSize: undefined,
    externalId: undefined,
    dedupId: undefined,
    layout: undefined,
    sharpProver: undefined,
    result: undefined,
    network: undefined,
    hints: undefined,
    programHash: undefined,
    mockFactHash: undefined,
    text: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--stone-air-run') {
      args.stoneAirRun = argv[++i];
    } else if (arg === '--out-dir') {
      args.outDir = argv[++i];
    } else if (arg === '--declared-job-size') {
      args.declaredJobSize = argv[++i];
    } else if (arg === '--external-id') {
      args.externalId = argv[++i];
    } else if (arg === '--dedup-id') {
      args.dedupId = argv[++i];
    } else if (arg === '--layout') {
      args.layout = argv[++i];
    } else if (arg === '--sharp-prover') {
      args.sharpProver = argv[++i];
    } else if (arg === '--result') {
      args.result = argv[++i];
    } else if (arg === '--network') {
      args.network = argv[++i];
    } else if (arg === '--hints') {
      args.hints = argv[++i];
    } else if (arg === '--program-hash') {
      args.programHash = argv[++i];
    } else if (arg === '--mock-fact-hash') {
      args.mockFactHash = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.stoneAirRun || !args.outDir) {
    throw new Error(`missing --stone-air-run or --out-dir\n\n${usage()}`);
  }

  return args;
}

function textReport(result) {
  const { manifest } = result;
  const lines = [
    `Atlantic bundle: ${result.outDir}`,
    `Status: ${manifest.status}`,
    `Circuit: ${manifest.source.circuit}`,
    `Stone executable: ${manifest.source.stoneExecutable}`,
    `Endpoint: ${manifest.endpoint}`,
    `Result: ${manifest.fields.result}`,
    `Network: ${manifest.fields.network}`,
    `Layout: ${manifest.fields.layout}`,
    `Declared job size: ${manifest.fields.declaredJobSize}`,
    `Program file: ${result.files.programFile}`,
    `Input file: ${result.files.inputFile}`,
    `Input felts: ${manifest.files.inputFile.feltCount}`,
    `Array wrapped: ${manifest.files.inputFile.arrayWrapped ? 'yes' : 'no'}`,
    `Submit script: ${result.files.submitScript}`,
  ];
  if (manifest.warnings.length > 0) {
    lines.push('');
    lines.push('Warnings:');
    for (const warning of manifest.warnings) {
      lines.push(`  - ${warning}`);
    }
  }
  lines.push('');
  lines.push('Submit with:');
  lines.push(`  ATLANTIC_API_KEY=... ${result.files.submitScript}`);
  return `${lines.join('\n')}\n`;
}

const args = parseArgs(process.argv.slice(2));
const result = createAtlanticQueryBundle(resolve(args.stoneAirRun), args.outDir, args);

if (args.text) {
  process.stdout.write(textReport(result));
} else {
  process.stdout.write(`${JSON.stringify(result.manifest, null, 2)}\n`);
}

