#!/usr/bin/env node
import { resolve } from 'node:path';
import { createNativeStwoHandoffPackage } from '../src/native-proof/handoff.mjs';

function usage() {
  return `Usage:
  node tools/export-native-stwo-handoff.mjs <proof-run.json> --out-dir <dir> [options]

Options:
  --program-hash <felt>        Cairo program hash for the executable.
  --proof-producer <name>      Expected to be scarb-stwo-local.
  --chain-id <felt|string>     Optional Starknet chain id context.
  --account-address <felt>     Optional account address context.
  --contract-address <felt>    Optional wrapper/target contract address context.
  --out-dir <dir>              Output directory for native proof handoff files.
  --text                       Print compact status.

The handoff package copies the proof metadata, prepared public output,
Scarb/Stwo proof JSON, logs, and writes:
  - native-handoff-manifest.json
  - native-readiness.json
  - native-proof-facts.json
  - public-output.json

This exporter prepares a native Starknet/S-two handoff artifact. It does not
broadcast a transaction unless the local Starknet client stack exposes the
native proof/proof_facts transaction fields.
`;
}

function parseArgs(argv) {
  const args = {
    proofRunPath: undefined,
    outDir: undefined,
    programHash: undefined,
    proofProducer: undefined,
    chainId: undefined,
    accountAddress: undefined,
    contractAddress: undefined,
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
    } else if (arg === '--proof-producer') {
      args.proofProducer = argv[++i];
    } else if (arg === '--chain-id') {
      args.chainId = argv[++i];
    } else if (arg === '--account-address') {
      args.accountAddress = argv[++i];
    } else if (arg === '--contract-address') {
      args.contractAddress = argv[++i];
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
  lines.push(`Native S-two handoff directory: ${result.outDir}`);
  lines.push(`Status: ${result.manifest.status}`);
  lines.push(`Circuit: ${result.manifest.circuit}`);
  lines.push(`Executable: ${result.manifest.executable}`);
  lines.push(`Execution ID: ${result.manifest.executionId}`);
  lines.push(`Proof producer: ${result.manifest.proofProducer}`);
  lines.push(`Proof artifact kind: ${result.manifest.proofArtifactKind}`);
  lines.push(`Local proof ready: ${result.manifest.localProofReady ? 'yes' : 'no'}`);
  lines.push(`Native handoff ready: ${result.manifest.nativeHandoffReady ? 'yes' : 'no'}`);
  lines.push(`Native broadcast ready: ${result.manifest.nativeBroadcastReady ? 'yes' : 'no'}`);
  lines.push(
    `starknet.js proof_facts support: ${
      result.manifest.starknetJs.supportsNativeProofTransaction ? 'yes' : 'no'
    }`,
  );
  if (result.readiness.hashes.programOutputFact) {
    lines.push(`Public output hash: ${result.readiness.hashes.programOutputFact.publicOutputHash}`);
    lines.push(`Program output fact hash: ${result.readiness.hashes.programOutputFact.factHash}`);
  }
  lines.push(`Candidate proof_facts felts: ${result.proofFacts.candidateProofFacts.felts.length}`);
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
  if (result.manifest.warnings.length > 0) {
    lines.push('');
    lines.push('Warnings:');
    for (const warning of result.manifest.warnings) {
      lines.push(`  - ${warning}`);
    }
  }
  return `${lines.join('\n')}\n`;
}

const args = parseArgs(process.argv.slice(2));
const result = createNativeStwoHandoffPackage(resolve(args.proofRunPath), args.outDir, args);

if (args.text) {
  process.stdout.write(textReport(result));
} else {
  process.stdout.write(`${JSON.stringify(result.manifest, null, 2)}\n`);
}
