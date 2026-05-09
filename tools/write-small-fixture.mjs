#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  SMALL_SYNTHETIC_CIRCUITS,
  buildSmallSyntheticFixture,
} from '../src/fixtures/small-amaci-fixtures.mjs';

function usage() {
  return `Usage:
  node tools/write-small-fixture.mjs --circuit <name> [--out <path>]

Circuits:
  ${SMALL_SYNTHETIC_CIRCUITS.join('\n  ')}
`;
}

function parseArgs(argv) {
  const args = { circuit: undefined, out: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--circuit') {
      args.circuit = argv[++i];
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!args.circuit || !SMALL_SYNTHETIC_CIRCUITS.includes(args.circuit)) {
    throw new Error(`missing or unsupported --circuit\n\n${usage()}`);
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const fixture = buildSmallSyntheticFixture(args.circuit);
const json = `${JSON.stringify(fixture, null, 2)}\n`;

if (args.out) {
  writeFileSync(resolve(args.out), json);
} else {
  process.stdout.write(json);
}
