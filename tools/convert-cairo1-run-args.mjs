#!/usr/bin/env node
import { convertScarbArgsJsonFile } from '../src/cairo-run-args.mjs';

function usage() {
  return `Usage:
  node tools/convert-cairo1-run-args.mjs <scarb-args.json> --out <args-file> [options]

Options:
  --flat   Write flat whitespace-separated felts instead of one Array<felt252>.
  --text   Print a short summary.
  --help   Show this help.

By default this writes one bracketed Array<felt252> argument, which is the input
shape required by cairo1-run --proof_mode entrypoints. The source JSON is the
array emitted by this repository's --cairo-args-out tools for scarb execute.`;
}

function parseArgs(argv) {
  const args = {
    inputPath: undefined,
    out: undefined,
    array: true,
    text: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--flat') {
      args.array = false;
    } else if (arg === '--text') {
      args.text = true;
    } else if (!args.inputPath) {
      args.inputPath = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.inputPath || !args.out) {
    throw new Error(`missing input or --out\n\n${usage()}`);
  }

  return args;
}

const args = parseArgs(process.argv.slice(2));
const result = convertScarbArgsJsonFile(args.inputPath, args.out, { array: args.array });

if (args.text) {
  console.log(`cairo1-run args: ${result.outputPath}`);
  console.log(`felt count: ${result.feltCount}`);
  console.log(`array wrapped: ${result.arrayWrapped ? 'yes' : 'no'}`);
}
