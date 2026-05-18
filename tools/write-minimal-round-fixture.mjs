#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { buildSmallNativeRoundFixture } from '../src/fixtures/small-amaci-fixtures.mjs';

function usage() {
  return `Usage:
  node tools/write-minimal-round-fixture.mjs [options]

Options:
  --out-dir <path>  Output directory. Default: target/minimal-native-round-fixture
  --text            Print generated paths and chain commitments.
`;
}

function parseArgs(argv) {
  const args = {
    outDir: 'target/minimal-native-round-fixture',
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
const fixture = buildSmallNativeRoundFixture();

mkdirSync(outDir, { recursive: true });
const processMessagesPath = resolve(outDir, 'process-messages-boundary-native.json');
const tallyPath = resolve(outDir, 'tally-native.json');
const chainPath = resolve(outDir, 'chain.json');

writeFileSync(processMessagesPath, `${JSON.stringify(fixture.processMessages, null, 2)}\n`);
writeFileSync(tallyPath, `${JSON.stringify(fixture.tally, null, 2)}\n`);
writeFileSync(chainPath, `${JSON.stringify(fixture.chain, null, 2)}\n`);

if (args.text) {
  const lines = [
    `Process messages input: ${processMessagesPath}`,
    `Tally input: ${tallyPath}`,
    `Chain state: ${chainPath}`,
    `Initial state commitment: ${fixture.chain.initialStateCommitment}`,
    `Process messages new state commitment: ${fixture.chain.processMessagesNewStateCommitment}`,
    `Tally state commitment: ${fixture.chain.tallyStateCommitment}`,
    `State link ok: ${fixture.chain.processMessagesToTallyStateMatches}`,
    `Initial tally commitment: ${fixture.chain.initialTallyCommitment}`,
    `Final tally commitment: ${fixture.chain.finalTallyCommitment}`,
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}
