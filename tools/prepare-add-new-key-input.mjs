#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { bigintToHex, decimalize } from '../src/compat/encoding.mjs';
import { evaluateAddNewKey } from '../src/add-new-key/add-new-key.mjs';
import {
  buildCairoAddNewKeyInput,
  serializeCairoAddNewKeyExecutableArgs,
} from '../src/add-new-key/cairo-input.mjs';

function usage() {
  return `Usage:
  node tools/prepare-add-new-key-input.mjs <add-new-key-input.json> [options]

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
    throw new Error(`missing AddNewKey input path\n\n${usage()}`);
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

function hexFields(fields) {
  return Object.fromEntries(Object.entries(fields).map(([key, value]) => {
    if (Array.isArray(value)) {
      return [key, value.map(bigintToHex)];
    }
    return [key, bigintToHex(value)];
  }));
}

const args = parseArgs(process.argv.slice(2));
const inputPath = resolve(args.inputPath);
const input = JSON.parse(readFileSync(inputPath, 'utf8'));
const evaluated = evaluateAddNewKey(input);
const cairoInput = buildCairoAddNewKeyInput(input, evaluated);
const cairoExecutableArgs = serializeCairoAddNewKeyExecutableArgs(cairoInput);

const output = {
  inputPath,
  params: evaluated.params,
  publicFields: serializeBigInts(evaluated.publicFields),
  publicFieldsHex: hexFields(evaluated.publicFields),
  publicOutput: {
    labels: evaluated.publicOutput.labels,
    felts: evaluated.publicOutput.decimalFelts,
    hexFelts: evaluated.publicOutput.felts.map(bigintToHex),
  },
  cairoInput,
  cairoExecutableArgs,
  derived: {
    nullifier: decimalize(evaluated.derived.nullifier),
    sharedKey: evaluated.derived.sharedKey.map(decimalize),
    sharedKeyHash: decimalize(evaluated.derived.sharedKeyHash),
    deactivateLeaf: decimalize(evaluated.derived.deactivateLeaf),
    deactivateRoot: decimalize(evaluated.derived.deactivateRoot),
    coordPubKeyHash: decimalize(evaluated.derived.coordPubKeyHash),
    newPubKeyHash: decimalize(evaluated.derived.newPubKeyHash),
    inputHash: decimalize(evaluated.derived.inputHash),
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
