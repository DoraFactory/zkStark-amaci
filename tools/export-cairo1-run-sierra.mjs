#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

function usage() {
  console.error(`Usage:
  node tools/export-cairo1-run-sierra.mjs <package.sierra.json> --function <debug-name> --out <runner.sierra.json> [--main-name <debug-name>]

Creates a cairo1-run-compatible Sierra artifact by renaming the selected
function debug_name so cairo1-run can discover it via the ::main suffix.
Any other package functions already ending in ::main are hidden so the exported
artifact has exactly one cairo1-run entrypoint.`);
}

function parseArgs(argv) {
  const opts = {
    input: '',
    functionName: '',
    out: '',
    mainName: 'zkstark_amaci_tally::stone_tally_votes::main',
  };

  const args = [...argv];
  opts.input = args.shift() ?? '';

  while (args.length > 0) {
    const arg = args.shift();
    switch (arg) {
      case '--function':
        opts.functionName = args.shift() ?? '';
        break;
      case '--main-name':
        opts.mainName = args.shift() ?? '';
        break;
      case '--out':
        opts.out = args.shift() ?? '';
        break;
      case '--help':
      case '-h':
        usage();
        process.exit(0);
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!opts.input || !opts.functionName || !opts.out) {
    usage();
    process.exit(1);
  }

  if (!opts.mainName.endsWith('::main')) {
    throw new Error(`--main-name must end with ::main: ${opts.mainName}`);
  }

  return opts;
}

function findFunction(program, debugName) {
  const matches = (program.funcs ?? [])
    .map((fn, index) => ({ fn, index }))
    .filter(({ fn }) => fn?.id?.debug_name === debugName);

  if (matches.length !== 1) {
    throw new Error(
      `expected exactly one Sierra function named ${debugName}, found ${matches.length}`,
    );
  }

  return matches[0];
}

function hideMainSuffix(debugName) {
  if (!debugName.endsWith('::main')) {
    return debugName;
  }

  return `${debugName.slice(0, -'::main'.length)}::__cairo1_run_hidden_main`;
}

const opts = parseArgs(process.argv.slice(2));
const source = JSON.parse(await readFile(opts.input, 'utf8'));
const { index } = findFunction(source, opts.functionName);

let hiddenMainCount = 0;
for (let i = 0; i < (source.funcs ?? []).length; i += 1) {
  if (i === index) {
    continue;
  }

  const debugName = source.funcs[i]?.id?.debug_name;
  if (typeof debugName === 'string' && debugName.endsWith('::main')) {
    source.funcs[i].id.debug_name = hideMainSuffix(debugName);
    hiddenMainCount += 1;
  }
}

source.funcs[index].id.debug_name = opts.mainName;

const exportedMains = (source.funcs ?? [])
  .map((fn) => fn?.id?.debug_name)
  .filter((debugName) => typeof debugName === 'string' && debugName.endsWith('::main'));

if (exportedMains.length !== 1 || exportedMains[0] !== opts.mainName) {
  throw new Error(
    `exported Sierra must contain exactly one ::main (${opts.mainName}); found ${exportedMains.length}: ${exportedMains.join(', ')}`,
  );
}

await mkdir(path.dirname(opts.out), { recursive: true });
await writeFile(opts.out, `${JSON.stringify(source)}\n`);

console.log(`runner Sierra: ${opts.out}`);
console.log(`main function: ${opts.mainName}`);
console.log(`hidden package main functions: ${hiddenMainCount}`);
