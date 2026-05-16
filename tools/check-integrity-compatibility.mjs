#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { analyzeProofRunIntegrityCompatibility } from '../src/integrity/proof-compatibility.mjs';

function usage() {
  return `Usage:
  node tools/check-integrity-compatibility.mjs <proof-run.json> [options]

Options:
  --program-hash <felt>              Child Cairo program hash.
  --bootloader-program-hash <felt>   Bootloader program hash for bootloaded facts.
  --verifier-config-hash <felt>      Integrity verifier config hash.
  --security-bits <n>                Security bits for verification hash.
  --proof-producer <name>            scarb-stwo-local, stone, or unknown.
  --integrity-calldata <path>        Serialized Integrity proof calldata artifact.
  --out <path>                       Write JSON report to a file.
  --text                             Print compact human-readable status.

This checks two separate questions:
  1. Can we compute the local wrapper binding hash from program_hash + public output?
  2. Does this proof run already contain the Stone/Integrity artifacts needed for submission?
`;
}

function parseArgs(argv) {
  const args = {
    proofRunPath: undefined,
    programHash: undefined,
    bootloaderProgramHash: undefined,
    verifierConfigHash: undefined,
    securityBits: undefined,
    proofProducer: undefined,
    integrityCalldata: undefined,
    out: undefined,
    text: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
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
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else if (!args.proofRunPath) {
      args.proofRunPath = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.proofRunPath) {
    throw new Error(`missing proof-run path\n\n${usage()}`);
  }
  return args;
}

function textReport(report) {
  const lines = [];
  lines.push(`Circuit: ${report.circuit ?? 'unknown'}`);
  lines.push(`Executable: ${report.executable ?? 'unknown'}`);
  lines.push(`Execution ID: ${report.executionId ?? 'unknown'}`);
  lines.push(`Proof producer: ${report.proofProducer}`);
  lines.push(`Proof artifact kind: ${report.proofArtifact.kind}`);
  lines.push(`Public output felts: ${report.publicOutput.feltCount}`);
  lines.push(`Proof JSON: ${report.proofFile.exists ? `${report.proofFile.sizeBytes} bytes` : 'missing'}`);
  lines.push(`Local scarb verification: ${report.localVerification.verified ? 'yes' : 'no'}`);
  lines.push(`Local proof ready: ${report.localProofReady ? 'yes' : 'no'}`);
  lines.push(`Local wrapper binding ready: ${report.localWrapperReady ? 'yes' : 'no'}`);
  lines.push(
    `Integrity calldata: ${
      report.integrityCalldata.exists
        ? `${report.integrityCalldata.feltCount} felts (${report.integrityCalldata.serializationType ?? 'unknown'})`
        : 'missing'
    }`,
  );
  if (report.integrityCalldata.settings?.verifierConfigHash) {
    lines.push(`Verifier config hash: ${report.integrityCalldata.settings.verifierConfigHash}`);
  }
  lines.push(`Integrity submission ready: ${report.integritySubmissionReady ? 'yes' : 'no'}`);
  if (report.hashes.plain) {
    lines.push(`Plain output hash: ${report.hashes.plain.outputHash}`);
    lines.push(`Plain fact hash: ${report.hashes.plain.factHash}`);
  }
  if (report.hashes.bootloaded) {
    lines.push(`Bootloaded output hash: ${report.hashes.bootloaded.bootloaderOutputHash}`);
    lines.push(`Bootloaded fact hash: ${report.hashes.bootloaded.factHash}`);
  }
  if (report.blockers.length > 0) {
    lines.push('');
    lines.push('Blockers:');
    for (const blocker of report.blockers) {
      lines.push(`  - ${blocker}`);
    }
  }
  if (report.warnings.length > 0) {
    lines.push('');
    lines.push('Warnings:');
    for (const warning of report.warnings) {
      lines.push(`  - ${warning}`);
    }
  }
  lines.push('');
  lines.push('Next steps:');
  for (const step of report.nextSteps) {
    lines.push(`  - ${step}`);
  }
  return `${lines.join('\n')}\n`;
}

const args = parseArgs(process.argv.slice(2));
const report = analyzeProofRunIntegrityCompatibility(resolve(args.proofRunPath), args);
const output = args.text ? textReport(report) : `${JSON.stringify(report, null, 2)}\n`;

if (args.out) {
  writeFileSync(resolve(args.out), output);
} else {
  process.stdout.write(output);
}
