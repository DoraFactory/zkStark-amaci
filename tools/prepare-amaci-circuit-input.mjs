#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { bigintToHex, decimalize } from '../src/compat/encoding.mjs';
import { evaluateTallyVotes } from '../src/tally/tally-votes.mjs';
import { buildCairoTallyInput, serializeCairoExecutableArgs } from '../src/cairo-input.mjs';
import {
  buildCairoProcessMessagesInput,
  buildCairoProcessMessageStepWithEcdhSignatureInput,
  buildCairoProcessMessagesStatefulInput,
  buildCairoProcessMessagesStatefulWithEcdhInput,
  buildCairoProcessMessagesStatefulWithEcdhSignatureInput,
  serializeCairoProcessMessagesExecutableArgs,
  serializeCairoProcessMessageStepWithEcdhSignatureExecutableArgs,
  serializeCairoProcessMessagesStatefulExecutableArgs,
  serializeCairoProcessMessagesStatefulWithEcdhExecutableArgs,
  serializeCairoProcessMessagesStatefulWithEcdhSignatureExecutableArgs,
} from '../src/msg/cairo-input.mjs';
import {
  evaluateProcessMessages,
  evaluateProcessMessagesStateful,
} from '../src/msg/process-messages.mjs';
import { evaluateAddNewKey } from '../src/add-new-key/add-new-key.mjs';
import {
  buildCairoAddNewKeyInput,
  serializeCairoAddNewKeyExecutableArgs,
} from '../src/add-new-key/cairo-input.mjs';
import {
  buildCairoProcessDeactivateMessagesBoundaryInput,
  buildCairoProcessDeactivateMessageStepInput,
  buildCairoProcessDeactivateMessagesStatefulInput,
  serializeCairoProcessDeactivateMessagesBoundaryExecutableArgs,
  serializeCairoProcessDeactivateMessageStepExecutableArgs,
  serializeCairoProcessDeactivateMessagesStatefulExecutableArgs,
} from '../src/deactivate/cairo-input.mjs';
import {
  evaluateProcessDeactivateMessages,
  evaluateProcessDeactivateMessagesStateful,
} from '../src/deactivate/process-deactivate-messages.mjs';

const PREPARERS = {
  tally: {
    executable: 'tally_votes',
    evaluate: evaluateTallyVotes,
    build: buildCairoTallyInput,
    serialize: serializeCairoExecutableArgs,
  },
  'process-messages-boundary': {
    executable: 'process_messages_boundary',
    evaluate: evaluateProcessMessages,
    build: buildCairoProcessMessagesInput,
    serialize: serializeCairoProcessMessagesExecutableArgs,
  },
  'process-messages-stateful': {
    executable: 'process_messages_stateful',
    evaluate: evaluateProcessMessagesStateful,
    build: buildCairoProcessMessagesStatefulInput,
    serialize: serializeCairoProcessMessagesStatefulExecutableArgs,
  },
  'process-messages-stateful-ecdh': {
    executable: 'process_messages_stateful_with_ecdh',
    evaluate: evaluateProcessMessagesStateful,
    build: buildCairoProcessMessagesStatefulWithEcdhInput,
    serialize: serializeCairoProcessMessagesStatefulWithEcdhExecutableArgs,
  },
  'process-messages-stateful-ecdh-signature': {
    executable: 'process_messages_stateful_with_ecdh_signature',
    evaluate: evaluateProcessMessagesStateful,
    build: buildCairoProcessMessagesStatefulWithEcdhSignatureInput,
    serialize: serializeCairoProcessMessagesStatefulWithEcdhSignatureExecutableArgs,
  },
  'process-message-step-ecdh-signature': {
    executable: 'process_message_step_with_ecdh_signature',
    evaluate: evaluateProcessMessagesStateful,
    build: (input, evaluated, options) =>
      buildCairoProcessMessageStepWithEcdhSignatureInput(
        input,
        options.messageIndex,
        evaluated,
      ),
    serialize: serializeCairoProcessMessageStepWithEcdhSignatureExecutableArgs,
    requiresMessageIndex: true,
  },
  'add-new-key': {
    executable: 'add_new_key',
    evaluate: evaluateAddNewKey,
    build: buildCairoAddNewKeyInput,
    serialize: serializeCairoAddNewKeyExecutableArgs,
  },
  'process-deactivate-boundary': {
    executable: 'process_deactivate_messages_boundary',
    evaluate: evaluateProcessDeactivateMessages,
    build: buildCairoProcessDeactivateMessagesBoundaryInput,
    serialize: serializeCairoProcessDeactivateMessagesBoundaryExecutableArgs,
  },
  'process-deactivate-step': {
    executable: 'process_deactivate_message_step',
    evaluate: evaluateProcessDeactivateMessagesStateful,
    build: (input, evaluated, options) =>
      buildCairoProcessDeactivateMessageStepInput(input, options.messageIndex, evaluated),
    serialize: serializeCairoProcessDeactivateMessageStepExecutableArgs,
    requiresMessageIndex: true,
  },
  'process-deactivate-stateful': {
    executable: 'process_deactivate_messages_stateful',
    evaluate: evaluateProcessDeactivateMessagesStateful,
    build: buildCairoProcessDeactivateMessagesStatefulInput,
    serialize: serializeCairoProcessDeactivateMessagesStatefulExecutableArgs,
  },
};

function usage() {
  return `Usage:
  node tools/prepare-amaci-circuit-input.mjs --circuit <name> <input.json> [options]

Circuits:
  ${Object.keys(PREPARERS).join('\n  ')}

Options:
  --out <path>             Write JSON output to a file.
  --cairo-input-out <path> Write Cairo runner input JSON to a file.
  --cairo-args-out <path>  Write scarb execute --arguments-file JSON.
  --message-index <n>      Message index for process-message-step-* circuits.
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
    if (!Number.isInteger(args.messageIndex) || args.messageIndex < 0 || args.messageIndex >= 5) {
      throw new Error('--message-index must be an integer in [0, 4]');
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
