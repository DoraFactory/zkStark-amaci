#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { buildSmallSyntheticFixture } from '../src/fixtures/small-amaci-fixtures.mjs';

const ROOT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const CIRCUITS = Object.freeze({
  'tally-native': {
    prepareCircuit: 'tally-native',
    executable: 'tally_votes_native',
    synthetic: false,
  },
  'add-new-key-native': {
    prepareCircuit: 'add-new-key-native',
    executable: 'add_new_key_native',
    synthetic: true,
    fixtureCircuit: 'add-new-key',
  },
  'process-messages-boundary-native': {
    prepareCircuit: 'process-messages-boundary-native',
    executable: 'process_messages_native_boundary',
    synthetic: true,
    fixtureCircuit: 'process-messages',
  },
  'process-messages-stage-native': {
    prepareCircuit: 'process-messages-stage-native',
    executable: 'process_messages_stage_native',
    synthetic: true,
    fixtureCircuit: 'process-messages',
  },
  'process-message-coord-key-native': {
    prepareCircuit: 'process-message-coord-key-native',
    executable: 'process_message_coord_key_native',
    synthetic: true,
    fixtureCircuit: 'process-messages',
  },
  'process-message-ecdh-native': {
    prepareCircuit: 'process-message-ecdh-native',
    executable: 'process_message_ecdh_native',
    synthetic: true,
    fixtureCircuit: 'process-messages',
    requiresMessageIndex: true,
  },
  'process-message-decrypt-native': {
    prepareCircuit: 'process-message-decrypt-native',
    executable: 'process_message_decrypt_native',
    synthetic: true,
    fixtureCircuit: 'process-messages',
    requiresMessageIndex: true,
  },
  'process-message-signature-native': {
    prepareCircuit: 'process-message-signature-native',
    executable: 'process_message_signature_native',
    synthetic: true,
    fixtureCircuit: 'process-messages',
    requiresMessageIndex: true,
  },
  'process-message-step-core-native': {
    prepareCircuit: 'process-message-step-core-native',
    executable: 'process_message_step_core_native',
    synthetic: true,
    fixtureCircuit: 'process-messages',
    requiresMessageIndex: true,
  },
  'process-deactivate-boundary-native': {
    prepareCircuit: 'process-deactivate-boundary-native',
    executable: 'process_deactivate_native_boundary',
    synthetic: true,
    fixtureCircuit: 'process-deactivate',
  },
  'process-deactivate-stage-native': {
    prepareCircuit: 'process-deactivate-stage-native',
    executable: 'process_deactivate_stage_native',
    synthetic: true,
    fixtureCircuit: 'process-deactivate',
  },
  'process-deactivate-coord-key-native': {
    prepareCircuit: 'process-deactivate-coord-key-native',
    executable: 'process_deactivate_coord_key_native',
    synthetic: true,
    fixtureCircuit: 'process-deactivate',
  },
  'process-deactivate-ecdh-command-native': {
    prepareCircuit: 'process-deactivate-ecdh-command-native',
    executable: 'process_deactivate_ecdh_native',
    synthetic: true,
    fixtureCircuit: 'process-deactivate',
    requiresMessageIndex: true,
  },
  'process-deactivate-ecdh-leaf-native': {
    prepareCircuit: 'process-deactivate-ecdh-leaf-native',
    executable: 'process_deactivate_ecdh_native',
    synthetic: true,
    fixtureCircuit: 'process-deactivate',
    requiresMessageIndex: true,
  },
  'process-deactivate-signature-native': {
    prepareCircuit: 'process-deactivate-signature-native',
    executable: 'process_deactivate_signature_native',
    synthetic: true,
    fixtureCircuit: 'process-deactivate',
    requiresMessageIndex: true,
  },
  'process-deactivate-decrypt-current-native': {
    prepareCircuit: 'process-deactivate-decrypt-current-native',
    executable: 'process_deactivate_decrypt_native',
    synthetic: true,
    fixtureCircuit: 'process-deactivate',
    requiresMessageIndex: true,
  },
  'process-deactivate-decrypt-new-native': {
    prepareCircuit: 'process-deactivate-decrypt-new-native',
    executable: 'process_deactivate_decrypt_native',
    synthetic: true,
    fixtureCircuit: 'process-deactivate',
    requiresMessageIndex: true,
  },
  'process-deactivate-step-core-native': {
    prepareCircuit: 'process-deactivate-step-core-native',
    executable: 'process_deactivate_step_core_native',
    synthetic: true,
    fixtureCircuit: 'process-deactivate',
    requiresMessageIndex: true,
  },
});

function usage() {
  return `Usage:
  node tools/run-cairo-execute.mjs --circuit <native-name> [input.json] [options]

Native circuits:
  ${Object.keys(CIRCUITS).join('\n  ')}

Options:
  --out-dir <path>      Directory for generated input, Cairo args, stdout, and metadata.
  --timeout-ms <n>      scarb execute timeout in milliseconds. Default: 300000.
  --message-index <n>   Message index for per-message native circuits. Default: 0.
  --no-resource-usage   Do not pass --print-resource-usage to scarb execute.
`;
}

function parseArgs(argv) {
  const args = {
    circuit: undefined,
    inputPath: undefined,
    outDir: undefined,
    timeoutMs: 300000,
    resourceUsage: true,
    messageIndex: 0,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--circuit') {
      args.circuit = argv[++i];
    } else if (arg === '--out-dir') {
      args.outDir = argv[++i];
    } else if (arg === '--timeout-ms') {
      args.timeoutMs = Number(argv[++i]);
    } else if (arg === '--message-index') {
      args.messageIndex = Number(argv[++i]);
    } else if (arg === '--no-resource-usage') {
      args.resourceUsage = false;
    } else if (!args.inputPath) {
      args.inputPath = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!args.circuit || !CIRCUITS[args.circuit]) {
    throw new Error(`missing or unsupported --circuit\n\n${usage()}`);
  }
  if (!Number.isSafeInteger(args.timeoutMs) || args.timeoutMs <= 0) {
    throw new Error('--timeout-ms must be a positive safe integer');
  }
  const maxMessageIndex = 2;
  if (!Number.isInteger(args.messageIndex) || args.messageIndex < 0 || args.messageIndex > maxMessageIndex) {
    throw new Error(`--message-index must be an integer in [0, ${maxMessageIndex}]`);
  }
  return args;
}

function run(command, commandArgs, options) {
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd,
    encoding: 'utf8',
    timeout: options.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function writeSyntheticInput(circuit, outPath) {
  const fixture = buildSmallSyntheticFixture(circuit);
  writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`);
}

function serializeBigInts(value) {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(serializeBigInts);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, serializeBigInts(val)]));
  }
  return value;
}

const args = parseArgs(process.argv.slice(2));
const circuit = CIRCUITS[args.circuit];

const outDir = resolve(args.outDir ?? `target/cairo-execute/${args.circuit}`);
ensureDir(outDir);

let inputPath = args.inputPath ? resolve(args.inputPath) : undefined;
let generatedInput = false;
if (!inputPath) {
  if (!circuit.synthetic) {
    throw new Error(`${args.circuit} requires an input JSON`);
  }
  inputPath = resolve(outDir, `${args.circuit}-small-input.json`);
  writeSyntheticInput(circuit.fixtureCircuit, inputPath);
  generatedInput = true;
}
if (!existsSync(inputPath)) {
  throw new Error(`input file not found: ${inputPath}`);
}

const preparedPath = resolve(outDir, `${args.circuit}-prepared.json`);
const cairoInputPath = resolve(outDir, `${args.circuit}-cairo-input.json`);
const cairoArgsPath = resolve(outDir, `${args.circuit}-cairo-args.json`);

const prepareArgs = [
  'tools/prepare-amaci-circuit-input.mjs',
  '--circuit',
  circuit.prepareCircuit,
  inputPath,
  '--out',
  preparedPath,
  '--cairo-input-out',
  cairoInputPath,
  '--cairo-args-out',
  cairoArgsPath,
];
if (circuit.requiresMessageIndex) {
  prepareArgs.push('--message-index', String(args.messageIndex));
}

const prepare = run('node', prepareArgs, { cwd: ROOT_DIR, timeoutMs: args.timeoutMs });
if (prepare.status !== 0) {
  process.stdout.write(prepare.stdout);
  process.stderr.write(prepare.stderr);
  process.exit(prepare.status ?? 1);
}

const executeArgs = [
  'execute',
  '--executable-name',
  circuit.executable,
  '--arguments-file',
  cairoArgsPath,
  '--print-program-output',
];
if (args.resourceUsage) {
  executeArgs.push('--print-resource-usage');
}

const execute = run('scarb', executeArgs, { cwd: resolve(ROOT_DIR, 'cairo'), timeoutMs: args.timeoutMs });

const stdoutPath = resolve(outDir, `${args.circuit}-stdout.log`);
const stderrPath = resolve(outDir, `${args.circuit}-stderr.log`);
writeFileSync(stdoutPath, execute.stdout);
writeFileSync(stderrPath, execute.stderr);

let expectedPublicOutputFelts = 0;
try {
  const prepared = JSON.parse(readFileSync(preparedPath, 'utf8'));
  expectedPublicOutputFelts = prepared.publicOutput?.felts?.length ?? 0;
} catch {
  expectedPublicOutputFelts = 0;
}

const metadata = {
  circuit: args.circuit,
  prepareCircuit: circuit.prepareCircuit,
  executable: circuit.executable,
  inputPath,
  generatedInput,
  messageIndex: circuit.requiresMessageIndex ? args.messageIndex : undefined,
  preparedPath,
  cairoInputPath,
  cairoArgsPath,
  stdoutPath,
  stderrPath,
  stdoutLog: stdoutPath,
  stderrLog: stderrPath,
  expectedPublicOutputFelts,
  status: execute.status,
  signal: execute.signal,
};
writeFileSync(resolve(outDir, 'execution-run.json'), `${JSON.stringify(serializeBigInts(metadata), null, 2)}\n`);

if (execute.status === 0) {
  process.stdout.write(`${JSON.stringify(serializeBigInts(metadata), null, 2)}\n`);
} else {
  process.stdout.write(execute.stdout);
  process.stderr.write(execute.stderr);
}
process.exit(execute.status ?? 0);
