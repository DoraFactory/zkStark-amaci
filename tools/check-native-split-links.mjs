#!/usr/bin/env node
import { createNativeSplitLinkReport, formatNativeSplitLinkReport } from '../src/native-proof/split-links.mjs';

function usage() {
  return `Usage:
  node tools/check-native-split-links.mjs <split-native-proofs.json> [--out <report.json>] [--text]

Checks native split ProcessMessages or ProcessDeactivate proof-run manifests for
public-output linkage across boundary, helper, and core proofs.
`;
}

function parseArgs(argv) {
  const args = {
    manifestPath: undefined,
    out: undefined,
    text: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--out') {
      args.out = argv[++index];
    } else if (arg === '--text') {
      args.text = true;
    } else if (!args.manifestPath) {
      args.manifestPath = arg;
    } else {
      throw new Error(`unknown argument: ${arg}\n\n${usage()}`);
    }
  }

  if (!args.manifestPath) {
    throw new Error(`missing split native proof manifest\n\n${usage()}`);
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const report = createNativeSplitLinkReport(args.manifestPath, { out: args.out });

if (args.text) {
  process.stdout.write(formatNativeSplitLinkReport(report));
} else if (!args.out) {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

if (!report.ok) {
  process.exitCode = 1;
}
