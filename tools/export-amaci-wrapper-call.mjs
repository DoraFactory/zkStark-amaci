#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { analyzeProofRunIntegrityCompatibility } from '../src/integrity/proof-compatibility.mjs';

function usage() {
  return `Usage:
  node tools/export-amaci-wrapper-call.mjs <proof-run.json> [options]

Options:
  --program-hash <felt>              Child Cairo program hash.
  --bootloader-program-hash <felt>   Bootloader program hash for bootloaded facts.
  --verifier-config-hash <felt>      Integrity verifier config hash.
  --security-bits <n>                Security bits.
  --proof-producer <name>            Default: value in proof-run.json or stone.
  --integrity-calldata <path>        Integrity calldata package used for readiness.
  --wrapper-address <address>        AMACI wrapper contract address.
  --out <path>                       Output wrapper call JSON.
  --text                             Print compact status.

The current native tally wrapper call is:
  submit_tally_fact(new_tally_commitment, input_hash, fact_hash)
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
    wrapperAddress: undefined,
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
    } else if (arg === '--wrapper-address') {
      args.wrapperAddress = argv[++i];
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

function labelValue(report, label) {
  const index = report.publicOutput.labels.indexOf(label);
  if (index === -1) {
    throw new Error(`public output does not contain ${label}`);
  }
  return report.publicOutput.hexFelts[index];
}

function command(wrapperAddress, calldata) {
  if (!wrapperAddress) {
    return undefined;
  }
  return [
    'sncast',
    '--wait',
    'invoke',
    '--fee-token',
    'eth',
    '--contract-address',
    wrapperAddress,
    '--function',
    'submit_tally_fact',
    '--calldata',
    calldata.join(' '),
  ];
}

const args = parseArgs(process.argv.slice(2));
const report = analyzeProofRunIntegrityCompatibility(resolve(args.proofRunPath), {
  programHash: args.programHash,
  bootloaderProgramHash: args.bootloaderProgramHash,
  verifierConfigHash: args.verifierConfigHash,
  securityBits: args.securityBits,
  proofProducer: args.proofProducer ?? 'stone',
  integrityCalldata: args.integrityCalldata,
});
const fact = report.hashes.bootloaded ?? report.hashes.plain;
if (!fact?.factHash) {
  throw new Error('cannot build wrapper call without computed fact hash');
}
const verificationHash = fact.verificationHash;
const newTallyCommitment = labelValue(report, 'new_tally_commitment');
const inputHash = labelValue(report, 'input_hash');
const calldata = [newTallyCommitment, inputHash, fact.factHash];

const output = {
  schema: 'zkstark-amaci.wrapper-call.v1',
  circuit: report.circuit,
  executable: report.executable,
  wrapperAddress: args.wrapperAddress,
  function: 'submit_tally_fact',
  calldata,
  newTallyCommitment,
  inputHash,
  factHash: fact.factHash,
  verificationHash,
  programHash: args.programHash,
  bootloaderProgramHash: args.bootloaderProgramHash,
  verifierConfigHash: args.verifierConfigHash,
  securityBits: args.securityBits,
  readiness: {
    localWrapperReady: report.localWrapperReady,
    integritySubmissionReady: report.integritySubmissionReady,
    blockers: report.blockers,
    warnings: report.warnings,
  },
  command: command(args.wrapperAddress, calldata),
};

if (args.out) {
  writeFileSync(resolve(args.out), `${JSON.stringify(output, null, 2)}\n`);
}

if (args.text) {
  process.stdout.write(
    [
      `Wrapper call: submit_tally_fact`,
      `new_tally_commitment: ${newTallyCommitment}`,
      `input_hash: ${inputHash}`,
      `fact_hash: ${fact.factHash}`,
      verificationHash ? `verification_hash: ${verificationHash}` : undefined,
      args.out ? `Wrapper call JSON: ${resolve(args.out)}` : undefined,
    ]
      .filter(Boolean)
      .join('\n') + '\n',
  );
} else {
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}
