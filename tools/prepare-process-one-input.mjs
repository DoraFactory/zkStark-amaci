#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { bigintToHex, decimalize } from '../src/compat/encoding.mjs';
import {
  buildCairoProcessOneStateTransitionInput,
  serializeCairoProcessOneStateTransitionExecutableArgs,
} from '../src/msg/cairo-input.mjs';
import { evaluateProcessOneStateTransition } from '../src/msg/process-one.mjs';

function usage() {
  return `Usage:
  node tools/prepare-process-one-input.mjs <process-one-input.json> [options]

Options:
  --out <path>             Write JSON output to a file.
  --cairo-input-out <path> Write Cairo runner input JSON to a file.
  --cairo-args-out <path>  Write scarb execute --arguments-file JSON.
`;
}

function parseArgs(argv) {
  const args = {
    inputPath: undefined,
    out: undefined,
    cairoInputOut: undefined,
    cairoArgsOut: undefined,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--cairo-input-out') {
      args.cairoInputOut = argv[++i];
    } else if (arg === '--cairo-args-out') {
      args.cairoArgsOut = argv[++i];
    } else if (!args.inputPath) {
      args.inputPath = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.inputPath) {
    throw new Error(`missing ProcessOne input path\n\n${usage()}`);
  }
  return args;
}

function serializeBigInts(value) {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map(serializeBigInts);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, serializeBigInts(val)]));
  }
  return value;
}

const args = parseArgs(process.argv.slice(2));
const inputPath = resolve(args.inputPath);
const input = JSON.parse(readFileSync(inputPath, 'utf8'));
const evaluated = evaluateProcessOneStateTransition(input);
const cairoInput = buildCairoProcessOneStateTransitionInput(input, evaluated);
const cairoExecutableArgs = serializeCairoProcessOneStateTransitionExecutableArgs(cairoInput);

const output = {
  inputPath,
  params: evaluated.params,
  cairoInput,
  cairoExecutableArgs,
  derived: {
    isValid: decimalize(evaluated.derived.isValid),
    stateIndex: decimalize(evaluated.derived.stateIndex),
    voteOptionIndex: decimalize(evaluated.derived.voteOptionIndex),
    currentVoteRoot: decimalize(evaluated.derived.currentVoteRoot),
    updatedVoteWeight: decimalize(evaluated.derived.updatedVoteWeight),
    newVoteOptionRoot: decimalize(evaluated.derived.newVoteOptionRoot),
    stateLeafHash: decimalize(evaluated.derived.stateLeafHash),
    newStateLeaf: evaluated.derived.newStateLeaf.map(decimalize),
    newStateLeafHash: decimalize(evaluated.derived.newStateLeafHash),
    newStateRoot: decimalize(evaluated.derived.newStateRoot),
    newStateRootHex: bigintToHex(evaluated.derived.newStateRoot),
  },
};

const json = `${JSON.stringify(serializeBigInts(output), null, 2)}\n`;
if (args.out) {
  writeFileSync(resolve(args.out), json);
} else {
  process.stdout.write(json);
}

if (args.cairoInputOut) {
  writeFileSync(resolve(args.cairoInputOut), `${JSON.stringify(cairoInput, null, 2)}\n`);
}

if (args.cairoArgsOut) {
  writeFileSync(resolve(args.cairoArgsOut), `${JSON.stringify(cairoExecutableArgs, null, 2)}\n`);
}
