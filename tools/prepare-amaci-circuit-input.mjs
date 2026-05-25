#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { bigintToHex, decimalize } from '../src/encoding.mjs';
import { evaluateNativeTallyVotes } from '../src/tally/native-tally-votes.mjs';
import {
  buildNativeCairoTallyInput,
  serializeNativeCairoTallyExecutableArgs,
} from '../src/native-cairo-input.mjs';
import {
  buildNativeCairoProcessMessageCoordKeyInput,
  buildNativeCairoProcessMessageDecryptInput,
  buildNativeCairoProcessMessageEcdhInput,
  buildNativeCairoProcessMessageSignatureInput,
  buildNativeCairoProcessMessageStepCoreInput,
  serializeNativeCairoProcessMessageCoordKeyExecutableArgs,
  serializeNativeCairoProcessMessageDecryptExecutableArgs,
  serializeNativeCairoProcessMessageEcdhExecutableArgs,
  serializeNativeCairoProcessMessageSignatureExecutableArgs,
  serializeNativeCairoProcessMessageStepCoreExecutableArgs,
} from '../src/msg/cairo-input.mjs';
import { evaluateProcessMessagesStateful } from '../src/msg/process-messages.mjs';
import {
  evaluateNativeProcessMessagesBoundary,
} from '../src/msg/native-process-messages.mjs';
import {
  buildNativeCairoProcessMessagesBoundaryInput,
  buildNativeCairoProcessMessagesStageInput,
  serializeNativeCairoProcessMessagesBoundaryExecutableArgs,
  serializeNativeCairoProcessMessagesStageExecutableArgs,
} from '../src/msg/native-cairo-input.mjs';
import { evaluateAddNewKey } from '../src/add-new-key/add-new-key.mjs';
import {
  buildNativeCairoAddNewKeyInput,
  serializeNativeCairoAddNewKeyExecutableArgs,
} from '../src/add-new-key/cairo-input.mjs';
import {
  buildNativeCairoProcessDeactivateCoordKeyInput,
  buildNativeCairoProcessDeactivateDecryptInput,
  buildNativeCairoProcessDeactivateEcdhInput,
  buildNativeCairoProcessDeactivateSignatureInput,
  buildNativeCairoProcessDeactivateStageInput,
  buildNativeCairoProcessDeactivateStepCoreInput,
  serializeNativeCairoProcessDeactivateCoordKeyExecutableArgs,
  serializeNativeCairoProcessDeactivateDecryptExecutableArgs,
  serializeNativeCairoProcessDeactivateEcdhExecutableArgs,
  serializeNativeCairoProcessDeactivateSignatureExecutableArgs,
  serializeNativeCairoProcessDeactivateStageExecutableArgs,
  serializeNativeCairoProcessDeactivateStepCoreExecutableArgs,
} from '../src/deactivate/cairo-input.mjs';
import { evaluateProcessDeactivateMessagesStateful } from '../src/deactivate/process-deactivate-messages.mjs';
import { evaluateNativeProcessDeactivateMessagesBoundary } from '../src/deactivate/native-process-deactivate-messages.mjs';
import {
  buildNativeCairoProcessDeactivateBoundaryInput,
  serializeNativeCairoProcessDeactivateBoundaryExecutableArgs,
} from '../src/deactivate/native-cairo-input.mjs';

const PREPARERS = {
  'tally-native': {
    executable: 'tally_votes_native',
    evaluate: evaluateNativeTallyVotes,
    build: buildNativeCairoTallyInput,
    serialize: serializeNativeCairoTallyExecutableArgs,
  },
  'add-new-key-native': {
    executable: 'add_new_key_native',
    evaluate: evaluateAddNewKey,
    build: buildNativeCairoAddNewKeyInput,
    serialize: serializeNativeCairoAddNewKeyExecutableArgs,
  },
  'process-messages-boundary-native': {
    executable: 'process_messages_native_boundary',
    evaluate: evaluateNativeProcessMessagesBoundary,
    build: buildNativeCairoProcessMessagesBoundaryInput,
    serialize: serializeNativeCairoProcessMessagesBoundaryExecutableArgs,
  },
  'process-messages-stage-native': {
    executable: 'process_messages_stage_native',
    evaluate: evaluateNativeProcessMessagesBoundary,
    build: buildNativeCairoProcessMessagesStageInput,
    serialize: serializeNativeCairoProcessMessagesStageExecutableArgs,
  },
  'process-message-coord-key-native': {
    executable: 'process_message_coord_key_native',
    evaluate: evaluateProcessMessagesStateful,
    build: buildNativeCairoProcessMessageCoordKeyInput,
    serialize: serializeNativeCairoProcessMessageCoordKeyExecutableArgs,
  },
  'process-message-ecdh-native': {
    executable: 'process_message_ecdh_native',
    evaluate: evaluateProcessMessagesStateful,
    build: (input, evaluated, options) =>
      buildNativeCairoProcessMessageEcdhInput(input, options.messageIndex, evaluated),
    serialize: serializeNativeCairoProcessMessageEcdhExecutableArgs,
    requiresMessageIndex: true,
  },
  'process-message-decrypt-native': {
    executable: 'process_message_decrypt_native',
    evaluate: evaluateProcessMessagesStateful,
    build: (input, evaluated, options) =>
      buildNativeCairoProcessMessageDecryptInput(input, options.messageIndex, evaluated),
    serialize: serializeNativeCairoProcessMessageDecryptExecutableArgs,
    requiresMessageIndex: true,
  },
  'process-message-signature-native': {
    executable: 'process_message_signature_native',
    evaluate: evaluateProcessMessagesStateful,
    build: (input, evaluated, options) =>
      buildNativeCairoProcessMessageSignatureInput(input, options.messageIndex, evaluated),
    serialize: serializeNativeCairoProcessMessageSignatureExecutableArgs,
    requiresMessageIndex: true,
  },
  'process-message-step-core-native': {
    executable: 'process_message_step_core_native',
    evaluate: evaluateProcessMessagesStateful,
    build: (input, evaluated, options) =>
      buildNativeCairoProcessMessageStepCoreInput(input, options.messageIndex, evaluated),
    serialize: serializeNativeCairoProcessMessageStepCoreExecutableArgs,
    requiresMessageIndex: true,
  },
  'process-deactivate-boundary-native': {
    executable: 'process_deactivate_native_boundary',
    evaluate: evaluateNativeProcessDeactivateMessagesBoundary,
    build: buildNativeCairoProcessDeactivateBoundaryInput,
    serialize: serializeNativeCairoProcessDeactivateBoundaryExecutableArgs,
  },
  'process-deactivate-stage-native': {
    executable: 'process_deactivate_stage_native',
    evaluate: evaluateNativeProcessDeactivateMessagesBoundary,
    build: buildNativeCairoProcessDeactivateStageInput,
    serialize: serializeNativeCairoProcessDeactivateStageExecutableArgs,
  },
  'process-deactivate-coord-key-native': {
    executable: 'process_deactivate_coord_key_native',
    evaluate: evaluateProcessDeactivateMessagesStateful,
    build: buildNativeCairoProcessDeactivateCoordKeyInput,
    serialize: serializeNativeCairoProcessDeactivateCoordKeyExecutableArgs,
  },
  'process-deactivate-ecdh-command-native': {
    executable: 'process_deactivate_ecdh_native',
    evaluate: evaluateProcessDeactivateMessagesStateful,
    build: (input, evaluated, options) =>
      buildNativeCairoProcessDeactivateEcdhInput(input, options.messageIndex, 'command', evaluated),
    serialize: serializeNativeCairoProcessDeactivateEcdhExecutableArgs,
    requiresMessageIndex: true,
  },
  'process-deactivate-ecdh-leaf-native': {
    executable: 'process_deactivate_ecdh_native',
    evaluate: evaluateProcessDeactivateMessagesStateful,
    build: (input, evaluated, options) =>
      buildNativeCairoProcessDeactivateEcdhInput(input, options.messageIndex, 'leaf', evaluated),
    serialize: serializeNativeCairoProcessDeactivateEcdhExecutableArgs,
    requiresMessageIndex: true,
  },
  'process-deactivate-signature-native': {
    executable: 'process_deactivate_signature_native',
    evaluate: evaluateProcessDeactivateMessagesStateful,
    build: (input, evaluated, options) =>
      buildNativeCairoProcessDeactivateSignatureInput(input, options.messageIndex, evaluated),
    serialize: serializeNativeCairoProcessDeactivateSignatureExecutableArgs,
    requiresMessageIndex: true,
  },
  'process-deactivate-decrypt-current-native': {
    executable: 'process_deactivate_decrypt_native',
    evaluate: evaluateProcessDeactivateMessagesStateful,
    build: (input, evaluated, options) =>
      buildNativeCairoProcessDeactivateDecryptInput(input, options.messageIndex, 'current', evaluated),
    serialize: serializeNativeCairoProcessDeactivateDecryptExecutableArgs,
    requiresMessageIndex: true,
  },
  'process-deactivate-decrypt-new-native': {
    executable: 'process_deactivate_decrypt_native',
    evaluate: evaluateProcessDeactivateMessagesStateful,
    build: (input, evaluated, options) =>
      buildNativeCairoProcessDeactivateDecryptInput(input, options.messageIndex, 'new', evaluated),
    serialize: serializeNativeCairoProcessDeactivateDecryptExecutableArgs,
    requiresMessageIndex: true,
  },
  'process-deactivate-step-core-native': {
    executable: 'process_deactivate_step_core_native',
    evaluate: evaluateProcessDeactivateMessagesStateful,
    build: (input, evaluated, options) =>
      buildNativeCairoProcessDeactivateStepCoreInput(input, options.messageIndex, evaluated),
    serialize: serializeNativeCairoProcessDeactivateStepCoreExecutableArgs,
    requiresMessageIndex: true,
  },
};

function usage() {
  return `Usage:
  node tools/prepare-amaci-circuit-input.mjs --circuit <native-name> <input.json> [options]

Native circuits:
  ${Object.keys(PREPARERS).join('\n  ')}

Options:
  --out <path>             Write JSON output to a file.
  --cairo-input-out <path> Write Cairo runner input JSON to a file.
  --cairo-args-out <path>  Write scarb execute --arguments-file JSON.
  --message-index <n>      Message index for per-message native circuits.
`;
}

function parseArgs(argv) {
  const args = {
    circuit: undefined,
    inputPath: undefined,
    out: undefined,
    cairoInputOut: undefined,
    cairoArgsOut: undefined,
    messageIndex: undefined,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--circuit') {
      args.circuit = argv[++i];
    } else if (arg === '--out') {
      args.out = argv[++i];
    } else if (arg === '--cairo-input-out') {
      args.cairoInputOut = argv[++i];
    } else if (arg === '--cairo-args-out') {
      args.cairoArgsOut = argv[++i];
    } else if (arg === '--message-index') {
      args.messageIndex = Number(argv[++i]);
    } else if (!args.inputPath) {
      args.inputPath = arg;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!args.circuit || !PREPARERS[args.circuit]) {
    throw new Error(`missing or unsupported --circuit\n\n${usage()}`);
  }
  if (!args.inputPath) {
    throw new Error(`missing input path\n\n${usage()}`);
  }
  const preparer = PREPARERS[args.circuit];
  if (preparer.requiresMessageIndex) {
    const maxMessageIndex = 2;
    if (
      !Number.isInteger(args.messageIndex) ||
      args.messageIndex < 0 ||
      args.messageIndex > maxMessageIndex
    ) {
      throw new Error(`--message-index must be an integer in [0, ${maxMessageIndex}]`);
    }
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
  return Object.fromEntries(Object.entries(fields).map(([key, value]) => {
    if (Array.isArray(value)) {
      return [key, value.map(bigintToHex)];
    }
    return [key, bigintToHex(value)];
  }));
}

function outputFromCairoInput(cairoInput, evaluated) {
  if (cairoInput.public_output_labels && cairoInput.public_output) {
    const felts = cairoInput.public_output.map((value) => BigInt(value));
    return {
      labels: cairoInput.public_output_labels,
      felts: felts.map(decimalize),
      hexFelts: felts.map(bigintToHex),
    };
  }
  if (evaluated.publicOutput === undefined) {
    return undefined;
  }
  return {
    labels: evaluated.publicOutput.labels,
    felts: evaluated.publicOutput.decimalFelts,
    hexFelts: evaluated.publicOutput.felts.map(bigintToHex),
  };
}

const args = parseArgs(process.argv.slice(2));
const preparer = PREPARERS[args.circuit];
const inputPath = resolve(args.inputPath);
const input = JSON.parse(readFileSync(inputPath, 'utf8'));
const evaluated = preparer.evaluate(input);
const cairoInput = preparer.build(input, evaluated, { messageIndex: args.messageIndex });
const cairoExecutableArgs = preparer.serialize(cairoInput);

const output = {
  circuit: args.circuit,
  executable: preparer.executable,
  inputPath,
  messageIndex: args.messageIndex,
  params: evaluated.params,
  publicFields: serializeBigInts(evaluated.publicFields ?? {}),
  publicFieldsHex: hexFields(evaluated.publicFields ?? {}),
  publicOutput: outputFromCairoInput(cairoInput, evaluated),
  cairoInput,
  cairoExecutableArgs,
  derived: serializeBigInts(evaluated.derived ?? {}),
};

const json = `${JSON.stringify(serializeBigInts(output), null, 2)}\n`;
if (args.out) {
  writeFileSync(resolve(args.out), json);
} else {
  process.stdout.write(json);
}

if (args.cairoInputOut) {
  writeFileSync(resolve(args.cairoInputOut), `${JSON.stringify(serializeBigInts(cairoInput), null, 2)}\n`);
}

if (args.cairoArgsOut) {
  writeFileSync(
    resolve(args.cairoArgsOut),
    `${JSON.stringify(serializeBigInts(cairoExecutableArgs), null, 2)}\n`,
  );
}
