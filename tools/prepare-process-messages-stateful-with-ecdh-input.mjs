#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { bigintToHex, decimalize, parseBigInt } from '../src/compat/encoding.mjs';
import {
  buildCairoProcessMessagesStatefulWithEcdhInput,
  serializeCairoProcessMessagesStatefulWithEcdhExecutableArgs,
} from '../src/msg/cairo-input.mjs';
import { evaluateProcessMessagesStateful } from '../src/msg/process-messages.mjs';
import {
  calculateBootloadedFactHash,
  calculatePlainFactHash,
  calculateVerificationHash,
  isIntegrityHashingAvailable,
} from '../src/integrity/hashes.mjs';

function usage() {
  return `Usage:
  node tools/prepare-process-messages-stateful-with-ecdh-input.mjs <process-messages-input.json> [options]

Options:
  --out <path>                     Write JSON output to a file.
  --cairo-input-out <path>         Write Cairo runner input JSON to a file.
  --cairo-args-out <path>          Write scarb execute --arguments-file JSON.
  --program-hash <felt>            Calculate a plain Integrity fact hash.
  --bootloader-program-hash <felt> Calculate a bootloaded Integrity fact hash.
  --verifier-config-hash <felt>    Calculate verification hash when fact hash is known.
  --security-bits <n>              Security bits for verification hash.
`;
}

function parseArgs(argv) {
  const args = {
    inputPath: undefined,
    out: undefined,
    cairoInputOut: undefined,
    cairoArgsOut: undefined,
    programHash: undefined,
    bootloaderProgramHash: undefined,
    verifierConfigHash: undefined,
    securityBits: undefined,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--cairo-input-out') {
      args.cairoInputOut = argv[++i];
    } else if (arg === '--cairo-args-out') {
      args.cairoArgsOut = argv[++i];
    } else if (arg === '--program-hash') {
      args.programHash = argv[++i];
    } else if (arg === '--bootloader-program-hash') {
      args.bootloaderProgramHash = argv[++i];
    } else if (arg === '--verifier-config-hash') {
      args.verifierConfigHash = argv[++i];
    } else if (arg === '--security-bits') {
      args.securityBits = argv[++i];
    } else if (!args.inputPath) {
      args.inputPath = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.inputPath) {
    throw new Error(`missing ProcessMessages stateful ECDH input path\n\n${usage()}`);
  }
  return args;
}

function serializeBigInts(value) {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map(serializeBigInts);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, serializeBigInts(val)]));
  }
  return value;
}

function hexFields(fields) {
  return Object.fromEntries(Object.entries(fields).map(([key, value]) => [key, bigintToHex(value)]));
}

const args = parseArgs(process.argv.slice(2));
const inputPath = resolve(args.inputPath);
const input = JSON.parse(readFileSync(inputPath, 'utf8'));
const evaluated = evaluateProcessMessagesStateful(input);
const cairoInput = buildCairoProcessMessagesStatefulWithEcdhInput(input, evaluated);
const cairoExecutableArgs = serializeCairoProcessMessagesStatefulWithEcdhExecutableArgs(cairoInput);

const output = {
  inputPath,
  params: evaluated.params,
  publicFields: serializeBigInts(evaluated.publicFields),
  publicFieldsHex: hexFields(evaluated.publicFields),
  publicOutput: {
    labels: evaluated.publicOutput.labels,
    felts: evaluated.publicOutput.decimalFelts,
    hexFelts: evaluated.publicOutput.felts.map(bigintToHex),
  },
  cairoInput,
  cairoExecutableArgs,
  derived: {
    coordPubKeyHash: decimalize(evaluated.derived.coordPubKeyHash),
    expectedPollId: decimalize(evaluated.derived.expectedPollId),
    inputHash: decimalize(evaluated.derived.inputHash),
    messageHashChain: evaluated.derived.messageHashChain.map(decimalize),
    stateTransitionNewStateRoot: decimalize(evaluated.derived.stateTransitionNewStateRoot),
  },
  integrity: {
    hashingAvailable: isIntegrityHashingAvailable(),
  },
};

if (args.programHash) {
  const plain = calculatePlainFactHash(args.programHash, evaluated.publicOutput.felts);
  output.integrity.plain = {
    programHash: bigintToHex(parseBigInt(args.programHash, 'programHash')),
    outputHash: bigintToHex(plain.outputHash),
    factHash: bigintToHex(plain.factHash),
  };

  if (args.verifierConfigHash && args.securityBits) {
    const verificationHash = calculateVerificationHash(
      plain.factHash,
      args.verifierConfigHash,
      args.securityBits,
    );
    output.integrity.plain.verificationHash = bigintToHex(verificationHash);
  }
}

if (args.programHash && args.bootloaderProgramHash) {
  const bootloaded = calculateBootloadedFactHash(
    args.bootloaderProgramHash,
    args.programHash,
    evaluated.publicOutput.felts,
  );
  output.integrity.bootloaded = {
    bootloaderProgramHash: bigintToHex(parseBigInt(args.bootloaderProgramHash, 'bootloaderProgramHash')),
    childProgramHash: bigintToHex(parseBigInt(args.programHash, 'programHash')),
    bootloaderOutput: bootloaded.bootloaderOutput.map(bigintToHex),
    bootloaderOutputHash: bigintToHex(bootloaded.bootloaderOutputHash),
    factHash: bigintToHex(bootloaded.factHash),
  };

  if (args.verifierConfigHash && args.securityBits) {
    const verificationHash = calculateVerificationHash(
      bootloaded.factHash,
      args.verifierConfigHash,
      args.securityBits,
    );
    output.integrity.bootloaded.verificationHash = bigintToHex(verificationHash);
  }
}

const json = `${JSON.stringify(serializeBigInts(output), null, 2)}\n`;
if (args.out) {
  writeFileSync(resolve(args.out), json);
} else {
  process.stdout.write(json);
}

if (args.cairoInputOut) {
  writeFileSync(resolve(args.cairoInputOut), `${JSON.stringify(cairoInput, null, 2)}\n`);
}

if (args.cairoArgsOut) {
  writeFileSync(resolve(args.cairoArgsOut), `${JSON.stringify(cairoExecutableArgs, null, 2)}\n`);
}
