import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeProofRunIntegrityCompatibility } from '../src/integrity/proof-compatibility.mjs';
import { isIntegrityHashingAvailable } from '../src/integrity/hashes.mjs';

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function setupProofRun() {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-integrity-'));
  const preparedJson = join(dir, 'tally-prepared.json');
  const proofJson = join(dir, 'proof.json');
  const proofRunJson = join(dir, 'proof-run.json');

  writeJson(preparedJson, {
    publicOutput: {
      labels: ['magic', 'version'],
      felts: ['1', '2', '3'],
    },
  });
  writeJson(proofJson, {
    proof: [],
  });
  writeJson(proofRunJson, {
    circuit: 'tally',
    executable: 'tally_votes',
    executionId: '7',
    proofJson,
    preparedJson,
  });

  return { dir, preparedJson, proofJson, proofRunJson };
}

test('classifies local scarb proof runs as not ready for direct Integrity submission', () => {
  const { proofRunJson } = setupProofRun();
  const report = analyzeProofRunIntegrityCompatibility(proofRunJson, {
    programHash: 0x1234n,
  });

  assert.equal(report.circuit, 'tally');
  assert.equal(report.publicOutput.feltCount, 3);
  assert.equal(report.proofFile.exists, true);
  assert.equal(report.proofProducer, 'scarb-stwo-local');
  assert.equal(report.integritySubmissionReady, false);
  assert.match(report.blockers.join('\n'), /Stone\/Integrity proof artifact/);
  assert.match(report.blockers.join('\n'), /Integrity proof calldata artifact/);
});

test('reports local wrapper readiness only when fact hashing can be computed', () => {
  const { proofRunJson } = setupProofRun();
  const report = analyzeProofRunIntegrityCompatibility(proofRunJson, {
    programHash: 0x1234n,
  });

  assert.equal(report.localWrapperReady, isIntegrityHashingAvailable());
  if (isIntegrityHashingAvailable()) {
    assert.ok(report.hashes.plain.factHash);
  } else {
    assert.match(report.blockers.join('\n'), /hashing helpers are unavailable/);
  }
});

test('requires a program hash before computing wrapper fact binding', () => {
  const { proofRunJson } = setupProofRun();
  const report = analyzeProofRunIntegrityCompatibility(proofRunJson);

  assert.equal(report.localWrapperReady, false);
  assert.match(report.blockers.join('\n'), /program hash is required/);
});
