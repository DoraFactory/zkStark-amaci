#!/usr/bin/env node
import { resolve } from 'node:path';
import { createIntegrityHandoffPackage } from '../src/integrity/handoff.mjs';

function usage() {
  return `Usage:
  node tools/export-integrity-handoff.mjs <proof-run.json> --out-dir <dir> [options]

Options:
  --program-hash <felt>              Child Cairo program hash.
  --bootloader-program-hash <felt>   Bootloader program hash for bootloaded facts.
  --verifier-config-hash <felt>      Integrity verifier config hash.
  --security-bits <n>                Security bits for verification hash.
  --proof-producer <name>            scarb-stwo-local, stone, or unknown.
  --integrity-calldata <path>        Serialized Integrity proof calldata artifact.
  --out-dir <dir>                    Output directory for handoff files.
  --text                             Print compact status.

The handoff package copies the proof metadata, prepared public output,
proof JSON, verify log, optional Integrity calldata, and writes:
  - handoff-manifest.json
  - integrity-readiness.json
  - public-output.json
  - wrapper-fact.json
`;
}

function parseArgs(argv) {
  const args = {
    proofRunPath: undefined,
    outDir: undefined,
    programHash: undefined,
    bootloaderProgramHash: undefined,
    verifierConfigHash: undefined,
    securityBits: undefined,
    proofProducer: undefined,
    integrityCalldata: undefined,
    text: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--out-dir') {
      args.outDir = argv[++i];
    } else if (arg === '--program-hash') {
      args.programHash = argv[++i];
    } else if (arg === '--bootloader-program-hash') {
      args.bootloaderProgramHash = argv[++i];
    } else if (arg === '--verifier-config-hash') {
      args.verifierConfigHash = argv[++i];
    } else if (arg === '--security-bits') {
      args.securityBits = argv[++i];
    } else if (arg === '--proof-producer') {
      args.proofProducer = argv[++i];
    } else if (arg === '--integrity-calldata') {
      args.integrityCalldata = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else if (!args.proofRunPath) {
      args.proofRunPath = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.proofRunPath || !args.outDir) {
    throw new Error(`missing proof-run path or --out-dir\n\n${usage()}`);
  }
  return args;
}

function textReport(result) {
  const lines = [];
  lines.push(`Handoff directory: ${result.outDir}`);
  lines.push(`Status: ${result.manifest.status}`);
  lines.push(`Circuit: ${result.manifest.circuit}`);
  lines.push(`Executable: ${result.manifest.executable}`);
  lines.push(`Execution ID: ${result.manifest.executionId}`);
  lines.push(`Proof producer: ${result.manifest.proofProducer}`);
  lines.push(`Proof artifact kind: ${result.manifest.proofArtifactKind}`);
  lines.push(`Local proof ready: ${result.manifest.localProofReady ? 'yes' : 'no'}`);
  lines.push(`Local wrapper binding ready: ${result.manifest.localWrapperReady ? 'yes' : 'no'}`);
  lines.push(`Integrity submission ready: ${result.manifest.integritySubmissionReady ? 'yes' : 'no'}`);
  if (result.readiness.hashes.plain) {
    lines.push(`Plain fact hash: ${result.readiness.hashes.plain.factHash}`);
  }
  if (result.readiness.hashes.bootloaded) {
    lines.push(`Bootloaded fact hash: ${result.readiness.hashes.bootloaded.factHash}`);
  }
  lines.push('');
  lines.push('Files:');
  for (const [label, path] of Object.entries(result.files)) {
    lines.push(`  ${label}: ${path}`);
  }
  if (result.manifest.blockers.length > 0) {
    lines.push('');
    lines.push('Blockers:');
    for (const blocker of result.manifest.blockers) {
      lines.push(`  - ${blocker}`);
    }
  }
  return `${lines.join('\n')}\n`;
}

const args = parseArgs(process.argv.slice(2));
const result = createIntegrityHandoffPackage(resolve(args.proofRunPath), args.outDir, args);

if (args.text) {
  process.stdout.write(textReport(result));
} else {
  process.stdout.write(`${JSON.stringify(result.manifest, null, 2)}\n`);
}
