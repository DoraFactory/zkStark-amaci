import { existsSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import {
  classifyAmaciFixture,
  discoverAmaciFixtures,
} from '../src/fixtures/amaci-fixture-discovery.mjs';

const smallTallyPath = fileURLToPath(
  new URL('../fixtures/tally-small/000000.json', import.meta.url),
);

function loadJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

test('classifies the small AMACI tally fixture as runnable', { skip: !existsSync(smallTallyPath) }, () => {
  const classification = classifyAmaciFixture(loadJson(smallTallyPath));

  assert.equal(classification.circuit, 'tally');
  assert.equal(classification.supported, true);
  assert.equal(classification.supportedProgram, 'tally_votes');
  assert.deepEqual(classification.shape, {
    stateLeafCount: 5,
    stateLeafWidth: 10,
    votesRows: 5,
    votesCols: 5,
    currentResultsCount: 5,
    statePathDepth: 1,
  });
});

test('discovers and validates runnable AMACI tally fixtures', { skip: !existsSync(smallTallyPath) }, () => {
  const report = discoverAmaciFixtures(dirname(smallTallyPath), { validate: true });
  const fixture = report.fixtures.find((entry) => entry.path === smallTallyPath);

  assert.ok(report.counts.tally >= 1);
  assert.ok(report.supportedCount >= 1);
  assert.equal(fixture.supported, true);
  assert.equal(fixture.validation.publicOutputFelts, 16);
  assert.ok(/^[0-9]+$/.test(fixture.validation.inputHash));
});

test('classifies larger ProcessMessages inputs as not yet directly runnable', () => {
  const classification = classifyAmaciFixture({
    currentStateCommitment: '1',
    msgs: Array.from({ length: 125 }, () => Array.from({ length: 10 }, () => '0')),
    encPubKeys: Array.from({ length: 125 }, () => ['0', '0']),
    currentStateLeaves: Array.from({ length: 25 }, () => Array.from({ length: 10 }, () => '0')),
    currentStateLeavesPathElements: Array.from({ length: 25 }, () => Array.from({ length: 4 }, () => ['0', '0', '0', '0'])),
    currentVoteWeightsPathElements: Array.from({ length: 25 }, () => Array.from({ length: 3 }, () => ['0', '0', '0', '0'])),
  });

  assert.equal(classification.circuit, 'process-messages');
  assert.equal(classification.supported, false);
  assert.match(classification.unsupportedReason, /ProcessMessages\(2,1,5\)/);
  assert.ok(classification.shape.messageCount > 5);
});
