#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { buildFiveSignupSimplifiedRoundFixture } from '../src/fixtures/small-amaci-fixtures.mjs';

function usage() {
  return `Usage:
  node tools/write-five-signup-round-fixture.mjs [options]

Options:
  --out-dir <path>  Output directory. Default: target/five-signup-simplified-round/fixture
  --text            Print generated paths and round summary.
`;
}

function parseArgs(argv) {
  const args = {
    outDir: 'target/five-signup-simplified-round/fixture',
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
const fixture = buildFiveSignupSimplifiedRoundFixture();

mkdirSync(outDir, { recursive: true });

const paths = {
  addNewKey: resolve(outDir, 'add-new-key-native.json'),
  processDeactivateStage: resolve(outDir, 'process-deactivate-stage-native.json'),
  processDeactivateBoundary: resolve(outDir, 'process-deactivate-boundary-native.json'),
  processMessagesStage0: resolve(outDir, 'process-messages-stage-native-0.json'),
  processMessagesBoundary0: resolve(outDir, 'process-messages-boundary-native-0.json'),
  processMessagesStage1: resolve(outDir, 'process-messages-stage-native-1.json'),
  processMessagesBoundary1: resolve(outDir, 'process-messages-boundary-native-1.json'),
  tally0: resolve(outDir, 'tally-native-0.json'),
  tally1: resolve(outDir, 'tally-native-1.json'),
  chain: resolve(outDir, 'chain.json'),
};

writeFileSync(paths.addNewKey, `${JSON.stringify(fixture.addNewKey, null, 2)}\n`);
writeFileSync(paths.processDeactivateStage, `${JSON.stringify(fixture.processDeactivate, null, 2)}\n`);
writeFileSync(paths.processDeactivateBoundary, `${JSON.stringify(fixture.processDeactivate, null, 2)}\n`);
writeFileSync(paths.processMessagesStage0, `${JSON.stringify(fixture.processMessages[0], null, 2)}\n`);
writeFileSync(paths.processMessagesBoundary0, `${JSON.stringify(fixture.processMessages[0], null, 2)}\n`);
writeFileSync(paths.processMessagesStage1, `${JSON.stringify(fixture.processMessages[1], null, 2)}\n`);
writeFileSync(paths.processMessagesBoundary1, `${JSON.stringify(fixture.processMessages[1], null, 2)}\n`);
writeFileSync(paths.tally0, `${JSON.stringify(fixture.tally[0], null, 2)}\n`);
writeFileSync(paths.tally1, `${JSON.stringify(fixture.tally[1], null, 2)}\n`);
writeFileSync(paths.chain, `${JSON.stringify(fixture.chain, null, 2)}\n`);

if (args.text) {
  const lines = [
    `Fixture dir: ${outDir}`,
    `Process deactivate: ${paths.processDeactivateStage}`,
    `Add new key: ${paths.addNewKey}`,
    `Process messages batch 0: ${paths.processMessagesStage0}`,
    `Process messages batch 1: ${paths.processMessagesStage1}`,
    `Tally batch 0: ${paths.tally0}`,
    `Tally batch 1: ${paths.tally1}`,
    `Chain state: ${paths.chain}`,
    `Signup count: ${fixture.chain.params.signupCount}`,
    `Deactivate messages: ${fixture.chain.params.deactivateMessageCount}`,
    `Published vote messages: ${fixture.chain.params.publishedVoteMessageCount}`,
    `Process message batches: ${fixture.chain.params.processMessageBatches}`,
    `Tally batches: ${fixture.chain.params.tallyBatches}`,
    `Expected raw results: ${fixture.chain.votes.expectedRawResults.join(', ')}`,
    `Final encoded results: ${fixture.chain.tally.at(-1).newResults.join(', ')}`,
    `All links ok: ${Object.values(fixture.chain.links).every(Boolean)}`,
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}
