#!/usr/bin/env node
import { resolve } from 'node:path';
import { buildIntegrityCalldataPackage } from '../src/integrity/calldata.mjs';

function usage() {
  return `Usage:
  node tools/serialize-integrity-calldata.mjs [options]

Options:
  --stone-proof <path>       Stone proof JSON accepted by Integrity proof_serializer.
  --integrity-repo <path>    Local HerodotusDev/integrity checkout.
  --proof-serializer <path>  Prebuilt proof_serializer binary.
  --raw-calldata <path>      Existing raw calldata file to wrap as JSON.
  --out <path>               Output integrity-calldata.json path.
  --text                     Print compact status.

Examples:
  node tools/serialize-integrity-calldata.mjs \\
    --stone-proof /path/to/stone-proof.json \\
    --integrity-repo ~/integrity \\
    --out /tmp/integrity-calldata.json \\
    --text

  node tools/serialize-integrity-calldata.mjs \\
    --raw-calldata ~/integrity/examples/calldata \\
    --out /tmp/integrity-calldata.json \\
    --text

Important:
  The current Scarb/Stwo proof.json is not a Stone proof. Use --stone-proof
  only with a Stone proof artifact accepted by Herodotus proof_serializer.
`;
}

function parseArgs(argv) {
  const args = {
    stoneProofPath: undefined,
    integrityRepo: undefined,
    proofSerializer: undefined,
    rawCalldataPath: undefined,
    out: undefined,
    text: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--stone-proof') {
      args.stoneProofPath = argv[++i];
    } else if (arg === '--integrity-repo') {
      args.integrityRepo = argv[++i];
    } else if (arg === '--proof-serializer') {
      args.proofSerializer = argv[++i];
    } else if (arg === '--raw-calldata') {
      args.rawCalldataPath = argv[++i];
    } else if (arg === '--out') {
      args.out = argv[++i];
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
const result = buildIntegrityCalldataPackage({
  stoneProofPath: args.stoneProofPath ? resolve(args.stoneProofPath) : undefined,
  rawCalldataPath: args.rawCalldataPath ? resolve(args.rawCalldataPath) : undefined,
  proofSerializer: args.proofSerializer ? resolve(args.proofSerializer) : undefined,
  integrityRepo: args.integrityRepo ? resolve(args.integrityRepo) : undefined,
  out: resolve(args.out),
});

if (args.text) {
  process.stdout.write(
    [
      `Integrity calldata: ${result.out}`,
      `Calldata felts: ${result.calldataFelts}`,
      `Proof producer: ${result.output.proofProducer}`,
      `Serializer mode: ${result.output.serializer.mode}`,
    ].join('\n') + '\n',
  );
} else {
  process.stdout.write(`${JSON.stringify(result.output, null, 2)}\n`);
}
