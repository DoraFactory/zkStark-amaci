#!/usr/bin/env node
import { resolve } from 'node:path';
import { buildIntegritySplitCalldataPackage } from '../src/integrity/split-calldata.mjs';

function usage() {
  return `Usage:
  node tools/serialize-integrity-split-calldata.mjs [options]

Options:
  --stone-proof <path>             Stone proof JSON.
  --split-calldata-dir <dir>       Existing split calldata directory to wrap.
  --stone-cli <path>               stone-cli binary for split Starknet serialization.
  --calldata-generator <dir>       HerodotusDev/integrity-calldata-generator checkout.
  --out-dir <dir>                  Output directory when generating split calldata.
  --out <path>                     Output split calldata package JSON.
  --layout <name>                  Default: recursive_with_poseidon.
  --hasher <name>                  Default: keccak_160_lsb.
  --stone-version <name>           Default: stone6.
  --memory-verification <name>     Default: cairo1.
  --text                           Print compact status.

Examples:
  node tools/serialize-integrity-split-calldata.mjs \\
    --stone-proof /proofs/stone-proof.json \\
    --calldata-generator ~/integrity-calldata-generator \\
    --out-dir /proofs/integrity-split \\
    --out /proofs/integrity-split-calldata.json \\
    --text

  node tools/serialize-integrity-split-calldata.mjs \\
    --split-calldata-dir /proofs/integrity-split/split-calldata \\
    --out /proofs/integrity-split-calldata.json \\
    --text
`;
}

function parseArgs(argv) {
  const args = {
    stoneProofPath: undefined,
    splitCalldataDir: undefined,
    outDir: undefined,
    out: undefined,
    stoneCli: undefined,
    calldataGeneratorDir: undefined,
    settings: {},
    text: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--stone-proof') {
      args.stoneProofPath = argv[++i];
    } else if (arg === '--split-calldata-dir') {
      args.splitCalldataDir = argv[++i];
    } else if (arg === '--out-dir') {
      args.outDir = argv[++i];
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--stone-cli') {
      args.stoneCli = argv[++i];
    } else if (arg === '--calldata-generator') {
      args.calldataGeneratorDir = argv[++i];
    } else if (arg === '--layout') {
      args.settings.layout = argv[++i];
    } else if (arg === '--hasher') {
      args.settings.hasher = argv[++i];
    } else if (arg === '--stone-version') {
      args.settings.stoneVersion = argv[++i];
    } else if (arg === '--memory-verification') {
      args.settings.memoryVerification = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.out) {
    throw new Error(`missing --out\n\n${usage()}`);
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const result = buildIntegritySplitCalldataPackage({
  stoneProofPath: args.stoneProofPath ? resolve(args.stoneProofPath) : undefined,
  splitCalldataDir: args.splitCalldataDir ? resolve(args.splitCalldataDir) : undefined,
  outDir: args.outDir ? resolve(args.outDir) : undefined,
  out: resolve(args.out),
  stoneCli: args.stoneCli ? resolve(args.stoneCli) : undefined,
  calldataGeneratorDir: args.calldataGeneratorDir
    ? resolve(args.calldataGeneratorDir)
    : undefined,
  settings: args.settings,
});

if (args.text) {
  process.stdout.write(
    [
      `Integrity split calldata: ${result.out}`,
      `Split calldata dir: ${result.splitCalldataDir}`,
      `Calldata felts: ${result.calldataFelts}`,
      `Step files: ${result.stepCount}`,
      `Layout: ${result.output.settings.layout}`,
      `Hasher: ${result.output.settings.hasher}`,
      `Stone version: ${result.output.settings.stoneVersion}`,
      `Memory verification: ${result.output.settings.memoryVerification}`,
      `Verifier config hash: ${result.output.settings.verifierConfigHash}`,
      `Serializer mode: ${result.output.serializer.mode}`,
    ].join('\n') + '\n',
  );
} else {
  process.stdout.write(`${JSON.stringify(result.output, null, 2)}\n`);
}
