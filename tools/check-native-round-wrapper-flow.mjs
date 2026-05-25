#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { simulateNativeRoundWrapperFlowFromDir } from '../src/wrapper/native-round-flow-model.mjs';

function usage() {
  return `Usage:
  node tools/check-native-round-wrapper-flow.mjs --fixture-dir <dir> [options]

Options:
  --fixture-dir <path>  Directory with full native round fixture JSON files.
  --out <path>          Optional JSON output path.
  --text                Print a compact summary.
  --help                Show this help.
`;
}

function parseArgs(argv) {
  const args = {
    fixtureDir: undefined,
    out: undefined,
    text: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--fixture-dir') {
      args.fixtureDir = argv[++i];
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!args.fixtureDir) {
    throw new Error('--fixture-dir is required');
  }
  return args;
}

function writeJson(path, value) {
  const absolute = resolve(path);
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, `${JSON.stringify(value, null, 2)}\n`);
  return absolute;
}

const args = parseArgs(process.argv.slice(2));
const result = simulateNativeRoundWrapperFlowFromDir(resolve(args.fixtureDir));
const out = args.out ? writeJson(args.out, result) : undefined;

if (args.text) {
  const lines = [
    `Native round wrapper flow: ${result.status}`,
    `Accepted facts: ${result.accepted.length}`,
    `Final state commitment: ${result.finalState.stateCommitment}`,
    `Final deactivate commitment: ${result.finalState.deactivateCommitment}`,
    `Final tally commitment: ${result.finalState.tallyCommitment}`,
    `Counters: keys=${result.finalState.keysAdded}, deactivate_batches=${result.finalState.deactivateBatchesProcessed}, message_batches=${result.finalState.messageBatchesProcessed}`,
  ];
  if (out) {
    lines.push(`Output: ${out}`);
  }
  process.stdout.write(`${lines.join('\n')}\n`);
}
