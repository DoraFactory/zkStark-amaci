#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { buildCairoTallyInput } from '../src/cairo-input.mjs';
import { collectTallyHashVectors } from '../src/hash-vectors.mjs';
import { evaluateTallyVotes } from '../src/tally/tally-votes.mjs';

function usage() {
  return `Usage:
  node tools/export-hash-vectors.mjs <tally-input.json> [options]

Options:
  --out <path>  Write JSON output to a file.
`;
}

function parseArgs(argv) {
  const args = {
    inputPath: undefined,
    out: undefined,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (!args.inputPath) {
      args.inputPath = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.inputPath) {
    throw new Error(`missing tally input path\n\n${usage()}`);
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const inputPath = resolve(args.inputPath);
const input = JSON.parse(readFileSync(inputPath, 'utf8'));
const evaluated = evaluateTallyVotes(input);
const cairoInput = buildCairoTallyInput(input, evaluated);
const vectors = collectTallyHashVectors(cairoInput.program_input);

const output = {
  inputPath,
  circuit: 'AMACI TallyVotes(2,1,1)',
  vectorCount: vectors.length,
  vectors,
};

const json = `${JSON.stringify(output, null, 2)}\n`;
if (args.out) {
  writeFileSync(resolve(args.out), json);
} else {
  process.stdout.write(json);
}
