#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  buildSmallAddNewKeyFixture,
  buildSmallNativeRoundFixture,
} from '../src/fixtures/small-amaci-fixtures.mjs';

function usage() {
  return `Usage:
  node tools/write-full-round-fixture.mjs [options]

Options:
  --out-dir <path>  Output directory. Default: target/full-native-round-fixture
  --text            Print generated paths and chain commitments.

This writes one coherent native round fixture:
  add-new-key-native.json
  process-messages-boundary-native.json
  tally-native.json
  chain.json

The process-messages file is intentionally reused for all per-message native
component circuits with --message-index 0..2.
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
const addNewKey = buildSmallAddNewKeyFixture();
const fixture = buildSmallNativeRoundFixture();

mkdirSync(outDir, { recursive: true });

const paths = {
  addNewKey: resolve(outDir, 'add-new-key-native.json'),
  processMessages: resolve(outDir, 'process-messages-boundary-native.json'),
  tally: resolve(outDir, 'tally-native.json'),
  chain: resolve(outDir, 'chain.json'),
};

writeFileSync(paths.addNewKey, `${JSON.stringify(addNewKey, null, 2)}\n`);
writeFileSync(paths.processMessages, `${JSON.stringify(fixture.processMessages, null, 2)}\n`);
writeFileSync(paths.tally, `${JSON.stringify(fixture.tally, null, 2)}\n`);
writeFileSync(paths.chain, `${JSON.stringify({
  ...fixture.chain,
  addNewKeyNullifier: addNewKey.nullifier,
  addNewKeyDeactivateRoot: addNewKey.deactivateRoot,
  addNewKeyInputHash: addNewKey.inputHash,
  fixtureNote:
    'add-new-key is accepted before process-messages in the mock round; its current proof output does not bind new_state_commitment, so the wrapper receives the linked process-messages initial state commitment as calldata.',
}, null, 2)}\n`);

if (args.text) {
  const lines = [
    `Add new key input: ${paths.addNewKey}`,
    `Process messages input: ${paths.processMessages}`,
    `Tally input: ${paths.tally}`,
    `Chain state: ${paths.chain}`,
    `Add key nullifier: ${addNewKey.nullifier}`,
    `Initial state commitment: ${fixture.chain.initialStateCommitment}`,
    `Process messages new state commitment: ${fixture.chain.processMessagesNewStateCommitment}`,
    `Tally state commitment: ${fixture.chain.tallyStateCommitment}`,
    `State link ok: ${fixture.chain.processMessagesToTallyStateMatches}`,
    `Initial deactivate commitment: ${fixture.chain.initialDeactivateCommitment}`,
    `Initial tally commitment: ${fixture.chain.initialTallyCommitment}`,
    `Final tally commitment: ${fixture.chain.finalTallyCommitment}`,
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}
