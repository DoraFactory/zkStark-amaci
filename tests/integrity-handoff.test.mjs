import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createIntegrityHandoffPackage } from '../src/integrity/handoff.mjs';

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function setupProofRun() {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-handoff-src-'));
  const preparedJson = join(dir, 'tally-prepared.json');
  const proofJson = join(dir, 'proof.json');
  const verifyLog = join(dir, 'verify.log');
  const proofRunJson = join(dir, 'proof-run.json');

  writeJson(preparedJson, {
    publicOutput: {
      labels: ['magic', 'version', 'value'],
      felts: ['1', '2', '3'],
      hexFelts: ['0x1', '0x2', '0x3'],
    },
  });
  writeJson(proofJson, { proof: [] });
  writeFileSync(verifyLog, 'Verified proof successfully\n');
  writeJson(proofRunJson, {
    circuit: 'tally',
    executable: 'tally_votes',
    executionId: '99',
    proofProducer: 'scarb-stwo-local',
    proofJson,
    preparedJson,
    verifyLog,
  });

  return { dir, proofRunJson };
}

test('exports a local proof handoff package with copied artifacts and readiness files', () => {
  const { proofRunJson } = setupProofRun();
  const outDir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-handoff-out-'));
  const result = createIntegrityHandoffPackage(proofRunJson, outDir, {
    programHash: 0x1234n,
  });

  assert.equal(result.manifest.schema, 'zkstark-amaci.integrity-handoff.v1');
  assert.equal(result.manifest.status, 'local_proof_and_wrapper_binding_ready');
  assert.equal(result.manifest.localProofReady, true);
  assert.equal(result.manifest.integritySubmissionReady, false);
  assert.ok(existsSync(result.files.manifest));
  assert.ok(existsSync(result.files.readiness));
  assert.ok(existsSync(result.files.publicOutput));
  assert.ok(existsSync(result.files.wrapperFact));
  assert.ok(existsSync(join(outDir, 'proof-run.json')));
  assert.ok(existsSync(join(outDir, 'prepared.json')));
  assert.ok(existsSync(join(outDir, 'proof.json')));
  assert.ok(existsSync(join(outDir, 'verify.log')));

  const wrapperFact = JSON.parse(readFileSync(result.files.wrapperFact, 'utf8'));
  assert.match(wrapperFact.note, /mock program hash/);
});

test('exports an Integrity-ready handoff when Stone calldata is supplied', () => {
  const { proofRunJson, dir } = setupProofRun();
  const calldataJson = join(dir, 'integrity-calldata.json');
  writeJson(calldataJson, {
    calldata: ['1', '0x2', '3'],
  });
  const outDir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-handoff-stone-'));
  const result = createIntegrityHandoffPackage(proofRunJson, outDir, {
    programHash: 0x1234n,
    proofProducer: 'stone',
    integrityCalldata: calldataJson,
  });

  assert.equal(result.manifest.proofProducer, 'stone');
  assert.equal(result.manifest.integritySubmissionReady, true);
  assert.equal(result.manifest.status, 'integrity_submission_ready');
  assert.ok(existsSync(join(outDir, 'integrity-calldata.json')));
});
