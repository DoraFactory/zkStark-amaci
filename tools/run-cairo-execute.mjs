#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { buildSmallSyntheticFixture } from '../src/fixtures/small-amaci-fixtures.mjs';

const ROOT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const CIRCUITS = Object.freeze({
  tally: {
    prepareCircuit: 'tally',
    executable: 'tally_votes',
    synthetic: false,
  },
  'tally-native': {
    prepareCircuit: 'tally-native',
    executable: 'tally_votes_native',
    synthetic: false,
  },
  'add-new-key': {
    prepareCircuit: 'add-new-key',
    executable: 'add_new_key',
    synthetic: true,
  },
  'process-messages': {
    prepareCircuit: 'process-messages-stateful-ecdh-signature',
    executable: 'process_messages_stateful_with_ecdh_signature',
    synthetic: true,
  },
  'process-message-step': {
    prepareCircuit: 'process-message-step-ecdh-signature',
    executable: 'process_message_step_with_ecdh_signature',
    synthetic: true,
    requiresMessageIndex: true,
  },
  'process-message-coord-key': {
    prepareCircuit: 'process-message-coord-key',
    executable: 'process_message_coord_key',
    synthetic: true,
  },
  'process-message-ecdh': {
    prepareCircuit: 'process-message-ecdh',
    executable: 'process_message_ecdh',
    synthetic: true,
    requiresMessageIndex: true,
  },
  'process-message-signature': {
    prepareCircuit: 'process-message-signature',
    executable: 'process_message_signature',
    synthetic: true,
    requiresMessageIndex: true,
  },
  'process-message-step-core': {
    prepareCircuit: 'process-message-step-core',
    executable: 'process_message_step_core',
    synthetic: true,
    requiresMessageIndex: true,
  },
  'process-deactivate': {
    prepareCircuit: 'process-deactivate-stateful',
    executable: 'process_deactivate_messages_stateful',
    synthetic: true,
  },
  'process-deactivate-step': {
    prepareCircuit: 'process-deactivate-step',
    executable: 'process_deactivate_message_step',
    synthetic: true,
    requiresMessageIndex: true,
  },
  'process-deactivate-coord-key': {
    prepareCircuit: 'process-deactivate-coord-key',
    executable: 'process_deactivate_coord_key',
    synthetic: true,
  },
  'process-deactivate-ecdh-command': {
    prepareCircuit: 'process-deactivate-ecdh-command',
    executable: 'process_deactivate_ecdh',
    synthetic: true,
    requiresMessageIndex: true,
  },
  'process-deactivate-ecdh-leaf': {
    prepareCircuit: 'process-deactivate-ecdh-leaf',
    executable: 'process_deactivate_ecdh',
    synthetic: true,
    requiresMessageIndex: true,
  },
  'process-deactivate-signature': {
    prepareCircuit: 'process-deactivate-signature',
    executable: 'process_deactivate_signature',
    synthetic: true,
    requiresMessageIndex: true,
  },
  'process-deactivate-decrypt-current': {
    prepareCircuit: 'process-deactivate-decrypt-current',
    executable: 'process_deactivate_decrypt',
    synthetic: true,
    requiresMessageIndex: true,
  },
  'process-deactivate-decrypt-new': {
    prepareCircuit: 'process-deactivate-decrypt-new',
    executable: 'process_deactivate_decrypt',
    synthetic: true,
    requiresMessageIndex: true,
  },
  'process-deactivate-step-core': {
    prepareCircuit: 'process-deactivate-step-core',
    executable: 'process_deactivate_step_core',
    synthetic: true,
    requiresMessageIndex: true,
  },
});

function usage() {
  return `Usage:
  node tools/run-cairo-execute.mjs --circuit <name> [input.json] [options]

Circuits:
  ${Object.keys(CIRCUITS).join('\n  ')}

Options:
  --out-dir <path>      Directory for generated input, Cairo args, stdout, and metadata.
  --timeout-ms <n>      scarb execute timeout in milliseconds. Default: 300000.
  --message-index <n>   Message index for process-message-* or process-deactivate-* step slices. Default: 0.
  --no-resource-usage   Do not pass --print-resource-usage to scarb execute.

If input.json is omitted for add-new-key, process-messages, or process-deactivate,
this tool generates the current small synthetic fixture for that circuit.
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
  if (!Number.isInteger(args.messageIndex) || args.messageIndex < 0 || args.messageIndex >= 5) {
    throw new Error('--message-index must be an integer in [0, 4]');
  }
  return args;
}

function run(command, commandArgs, options) {
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 512,
    timeout: options.timeoutMs,
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

function ensureInput(args, circuit, outDir) {
  if (args.inputPath) {
    const inputPath = resolve(args.inputPath);
    if (!existsSync(inputPath)) {
      throw new Error(`input file does not exist: ${inputPath}`);
    }
    return { inputPath, generatedInput: false };
  }
  if (!circuit.synthetic) {
    throw new Error(`input.json is required for ${args.circuit}`);
  }
  const inputPath = resolve(outDir, `${args.circuit}-small-input.json`);
  const syntheticCircuit = args.circuit === 'process-message-step' || args.circuit.startsWith('process-message-')
    ? 'process-messages'
    : args.circuit === 'process-deactivate-step' || args.circuit.startsWith('process-deactivate-')
      ? 'process-deactivate'
      : args.circuit;
  writeFileSync(inputPath, `${JSON.stringify(buildSmallSyntheticFixture(syntheticCircuit), null, 2)}\n`);
  return { inputPath, generatedInput: true };
}

const args = parseArgs(process.argv.slice(2));
const circuit = CIRCUITS[args.circuit];
const outDir = resolve(args.outDir ?? `${ROOT_DIR}/target/cairo-execute/${args.circuit}`);
mkdirSync(outDir, { recursive: true });

const { inputPath, generatedInput } = ensureInput(args, circuit, outDir);
const preparedJson = resolve(outDir, `${args.circuit}-prepared.json`);
const cairoInputJson = resolve(outDir, `${args.circuit}-cairo-input.json`);
const cairoArgsJson = resolve(outDir, `${args.circuit}-cairo-args.json`);
const stdoutPath = resolve(outDir, `${args.circuit}-execute.stdout.txt`);
const stderrPath = resolve(outDir, `${args.circuit}-execute.stderr.txt`);
const metadataPath = resolve(outDir, `${args.circuit}-execute.json`);

const prepareResult = run(
  process.execPath,
  [
    `${ROOT_DIR}/tools/prepare-amaci-circuit-input.mjs`,
    '--circuit',
    circuit.prepareCircuit,
    inputPath,
    '--out',
    preparedJson,
    '--cairo-input-out',
    cairoInputJson,
    '--cairo-args-out',
    cairoArgsJson,
    ...(circuit.requiresMessageIndex ? ['--message-index', String(args.messageIndex)] : []),
  ],
  { cwd: ROOT_DIR, timeoutMs: args.timeoutMs },
);
if (prepareResult.status !== 0) {
  process.stdout.write(prepareResult.stdout);
  process.stderr.write(prepareResult.stderr);
  process.exit(prepareResult.status ?? 1);
}

const executeArgs = [
  'execute',
  '--executable-name',
  circuit.executable,
  '--arguments-file',
  cairoArgsJson,
  '--print-program-output',
];
if (args.resourceUsage) {
  executeArgs.push('--print-resource-usage');
}

const executeResult = run('scarb', executeArgs, {
  cwd: `${ROOT_DIR}/cairo`,
  timeoutMs: args.timeoutMs,
});
writeFileSync(stdoutPath, executeResult.stdout);
writeFileSync(stderrPath, executeResult.stderr);

const prepared = JSON.parse(readFileSync(preparedJson, 'utf8'));
const metadata = {
  circuit: args.circuit,
  prepareCircuit: circuit.prepareCircuit,
  executable: circuit.executable,
  messageIndex: circuit.requiresMessageIndex ? args.messageIndex : undefined,
  generatedInput,
  inputPath,
  preparedJson,
  cairoInputJson,
  cairoArgsJson,
  stdoutPath,
  stderrPath,
  status: executeResult.status,
  signal: executeResult.signal,
  expectedPublicOutputFelts:
    prepared.publicOutput?.felts?.length ?? prepared.publicOutput?.length ?? undefined,
};
writeFileSync(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`);

if (executeResult.status !== 0) {
  process.stdout.write(executeResult.stdout);
  process.stderr.write(executeResult.stderr);
  process.exit(executeResult.status ?? 1);
}

process.stdout.write(`${JSON.stringify(metadata, null, 2)}\n`);
