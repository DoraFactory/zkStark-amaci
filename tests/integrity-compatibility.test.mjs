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
  const verifyLog = join(dir, 'tally-verify.log');
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
  writeFileSync(verifyLog, '   Verifying zkstark_amaci_tally\n    Verified proof successfully\n');
  writeJson(proofRunJson, {
    circuit: 'tally',
    executable: 'tally_votes',
    executionId: '7',
    proofJson,
    preparedJson,
    verifyLog,
  });

  return { dir, preparedJson, proofJson, verifyLog, proofRunJson };
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
  assert.equal(report.proofArtifact.kind, 'scarb-stwo-local-proof');
  assert.equal(report.localVerification.verified, true);
  assert.equal(report.localProofReady, true);
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

test('accepts declared Stone proof runs only when calldata is present and felt-shaped', () => {
  const { proofRunJson, dir } = setupProofRun();
  const calldataJson = join(dir, 'integrity-calldata.json');
  writeJson(calldataJson, {
    calldata: ['0x1', '2', '3'],
  });

  const report = analyzeProofRunIntegrityCompatibility(proofRunJson, {
    programHash: 0x1234n,
    proofProducer: 'stone',
    integrityCalldata: calldataJson,
  });

  assert.equal(report.proofArtifact.kind, 'stone-proof-artifact');
  assert.equal(report.integrityCalldata.validFeltArray, true);
  assert.equal(report.integrityCalldata.feltCount, 3);
  assert.equal(report.integritySubmissionReady, isIntegrityHashingAvailable());
  if (!isIntegrityHashingAvailable()) {
    assert.match(report.blockers.join('\n'), /hashing helpers are unavailable/);
  }
});

test('rejects declared Stone proof runs with malformed calldata', () => {
  const { proofRunJson, dir } = setupProofRun();
  const calldataJson = join(dir, 'integrity-calldata.json');
  writeJson(calldataJson, {
    calldata: ['0x1', { bad: true }],
  });

  const report = analyzeProofRunIntegrityCompatibility(proofRunJson, {
    programHash: 0x1234n,
    proofProducer: 'stone',
    integrityCalldata: calldataJson,
  });

  assert.equal(report.integrityCalldata.validFeltArray, false);
  assert.equal(report.integritySubmissionReady, false);
  assert.match(report.blockers.join('\n'), /not a non-empty felt array/);
});
