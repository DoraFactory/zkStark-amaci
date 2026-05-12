#!/usr/bin/env node
import { createProofArtifactInventory } from '../src/native-proof/inventory.mjs';

function usage() {
  return `Usage:
  node tools/export-proof-artifact-inventory.mjs <proof-root> [options]

Options:
  --target-dev <dir>   Directory containing *.executable.json artifacts.
                       Default: cairo/target/dev
  --out <path>         Write inventory JSON to a file.
  --text               Print compact text summary.

This inventories local Scarb/Stwo proof runs and their compiled executable
artifacts. It records file hashes and local executable program digests, but it
does not derive a canonical Starknet native proof_facts program hash.
`;
}

function parseArgs(argv) {
  const args = {
    rootDir: undefined,
    targetDevDir: undefined,
    out: undefined,
    text: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--target-dev') {
      args.targetDevDir = argv[++i];
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else if (!args.rootDir) {
      args.rootDir = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.rootDir) {
    throw new Error(`missing proof-root\n\n${usage()}`);
  }
  return args;
}

function textReport(inventory) {
  const lines = [];
  lines.push(`Status: ${inventory.status}`);
  lines.push(`Proof root: ${inventory.rootDir}`);
  lines.push(`Target dev: ${inventory.targetDevDir}`);
  lines.push(
    `Proof runs: ${inventory.counts.verifiedProofRuns}/${inventory.counts.proofRuns} verified`,
  );
  lines.push(`Unique executables: ${inventory.counts.uniqueExecutables}`);
  lines.push(`Blockers: ${inventory.counts.blockers}`);
  lines.push('');
  lines.push('Executables:');
  for (const executable of inventory.executables) {
    lines.push(
      `  ${executable.executable} size=${executable.sizeBytes ?? 'missing'}B ` +
        `bytecode=${executable.programBytecodeLength ?? '?'} ` +
        `sha256=${executable.sha256 ?? 'missing'} ` +
        `programDigest=${executable.localProgramDigest ?? 'missing'}`,
    );
  }
  const blocked = inventory.proofRuns.filter((run) => run.blockers.length > 0);
  if (blocked.length > 0) {
    lines.push('');
    lines.push('Blocked proof runs:');
    for (const run of blocked) {
      lines.push(`  ${run.proofRun.relativePath}: ${run.blockers.join('; ')}`);
    }
  }
  lines.push('');
  lines.push('Warnings:');
  for (const warning of inventory.warnings) {
    lines.push(`  - ${warning}`);
  }
  return `${lines.join('\n')}\n`;
}

const args = parseArgs(process.argv.slice(2));
const inventory = createProofArtifactInventory(args.rootDir, {
  targetDevDir: args.targetDevDir,
  out: args.out,
});

if (args.text) {
  process.stdout.write(textReport(inventory));
} else {
  process.stdout.write(`${JSON.stringify(inventory, null, 2)}\n`);
}
