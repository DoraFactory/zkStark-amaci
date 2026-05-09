#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { discoverAmaciFixtures } from '../src/fixtures/amaci-fixture-discovery.mjs';

function usage() {
  return `Usage:
  node tools/discover-amaci-fixtures.mjs <fixture-root> [options]

Options:
  --out <path>   Write JSON report to a file.
  --validate     Validate compatible small fixtures with the JS reference model.
`;
}

function parseArgs(argv) {
  const args = { root: undefined, out: undefined, validate: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--validate') {
      args.validate = true;
    } else if (!args.root) {
      args.root = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!args.root) {
    throw new Error(`missing fixture root\n\n${usage()}`);
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const report = discoverAmaciFixtures(args.root, { validate: args.validate });
const json = `${JSON.stringify(report, null, 2)}\n`;

if (args.out) {
  writeFileSync(resolve(args.out), json);
} else {
  process.stdout.write(json);
}
