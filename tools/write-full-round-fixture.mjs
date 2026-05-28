#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  buildSmallNativeLifecycleRoundFixture,
} from '../src/fixtures/small-amaci-fixtures.mjs';

function usage() {
  return `Usage:
  node tools/write-full-round-fixture.mjs [options]

Options:
  --out-dir <path>  Output directory. Default: target/full-native-round-fixture
  --text            Print generated paths and chain commitments.

This writes one coherent native lifecycle fixture:
  process-deactivate-stage-native.json
  process-deactivate-boundary-native.json
  add-new-key-native.json
  process-messages-stage-native.json
  process-messages-boundary-native.json
  tally-native.json
  chain.json

The generated flow is signup -> deactivate -> processDeactivate -> addNewKey
-> vote -> processMessages -> tally, with signupCount=3 and messageBatchSize=3.
`;
}

function parseArgs(argv) {
  const args = {
    outDir: 'target/full-native-round-fixture',
    text: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    } else if (arg === '--out-dir') {
      args.outDir = argv[++i];
    } else if (arg === '--text') {
      args.text = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const outDir = resolve(args.outDir);
const fixture = buildSmallNativeLifecycleRoundFixture();

mkdirSync(outDir, { recursive: true });

const paths = {
  addNewKey: resolve(outDir, 'add-new-key-native.json'),
  processDeactivateStage: resolve(outDir, 'process-deactivate-stage-native.json'),
  processDeactivateBoundary: resolve(outDir, 'process-deactivate-boundary-native.json'),
  processMessagesStage: resolve(outDir, 'process-messages-stage-native.json'),
  processMessagesBoundary: resolve(outDir, 'process-messages-boundary-native.json'),
  tally: resolve(outDir, 'tally-native.json'),
  chain: resolve(outDir, 'chain.json'),
};

writeFileSync(paths.addNewKey, `${JSON.stringify(fixture.addNewKey, null, 2)}\n`);
writeFileSync(paths.processDeactivateStage, `${JSON.stringify(fixture.processDeactivate, null, 2)}\n`);
writeFileSync(paths.processDeactivateBoundary, `${JSON.stringify(fixture.processDeactivate, null, 2)}\n`);
writeFileSync(paths.processMessagesStage, `${JSON.stringify(fixture.processMessages, null, 2)}\n`);
writeFileSync(paths.processMessagesBoundary, `${JSON.stringify(fixture.processMessages, null, 2)}\n`);
writeFileSync(paths.tally, `${JSON.stringify(fixture.tally, null, 2)}\n`);
writeFileSync(paths.chain, `${JSON.stringify(fixture.chain, null, 2)}\n`);

if (args.text) {
  const lines = [
    `Process deactivate stage input: ${paths.processDeactivateStage}`,
    `Process deactivate boundary input: ${paths.processDeactivateBoundary}`,
    `Add new key input: ${paths.addNewKey}`,
    `Process messages stage input: ${paths.processMessagesStage}`,
    `Process messages boundary input: ${paths.processMessagesBoundary}`,
    `Tally input: ${paths.tally}`,
    `Chain state: ${paths.chain}`,
    `Signup count: ${fixture.chain.params.signupCount}`,
    `Message batch size: ${fixture.chain.params.messageBatchSize}`,
    `Initial state commitment: ${fixture.chain.signup.initialStateCommitment}`,
    `Deactivate -> processMsg link ok: ${fixture.chain.links.deactivateToProcessMessages}`,
    `ProcessMsg -> tally link ok: ${fixture.chain.links.processMessagesToTallyState}`,
    `Process messages new state commitment: ${fixture.chain.processMessages.newStateCommitment}`,
    `Final tally commitment: ${fixture.chain.tally.newTallyCommitment}`,
    `Final tally results: ${fixture.chain.tally.newResults.join(', ')}`,
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}
