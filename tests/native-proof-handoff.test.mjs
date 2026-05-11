import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeNativeStwoHandoff,
  createNativeStwoHandoffPackage,
} from '../src/native-proof/handoff.mjs';
import { bigintToHex } from '../src/compat/encoding.mjs';
import { calculatePlainFactHash, isIntegrityHashingAvailable } from '../src/integrity/hashes.mjs';

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function setupProofRun({ verified = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-native-src-'));
  const preparedJson = join(dir, 'tally-prepared.json');
  const proofJson = join(dir, 'proof.json');
  const proveLog = join(dir, 'prove.log');
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
  writeFileSync(proveLog, 'proof generated\n');
  writeFileSync(verifyLog, verified ? 'Verified proof successfully\n' : 'verification failed\n');
  writeJson(proofRunJson, {
    circuit: 'tally',
    executable: 'tally_votes',
    executionId: '99',
    proofProducer: 'scarb-stwo-local',
    proofJson,
    preparedJson,
    proveLog,
    verifyLog,
  });

  return { dir, proofRunJson, verifyLog };
}

test('exports a native S-two handoff package from a locally verified Scarb/Stwo proof', () => {
  const { proofRunJson } = setupProofRun();
  const outDir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-native-out-'));
  const result = createNativeStwoHandoffPackage(proofRunJson, outDir, {
    programHash: 0x1234n,
  });

  assert.equal(result.manifest.schema, 'zkstark-amaci.native-stwo-handoff.v1');
  assert.equal(result.manifest.localProofReady, true);
  assert.equal(result.manifest.nativeHandoffReady, isIntegrityHashingAvailable());
  assert.equal(
    result.manifest.nativeBroadcastReady,
    result.manifest.nativeHandoffReady &&
      result.manifest.starknetJs.supportsNativeProofTransaction &&
      result.manifest.proofJsonMappedToTransaction,
  );
  assert.equal(
    result.manifest.status,
    result.manifest.nativeHandoffReady ? 'native_handoff_ready' : 'local_proof_ready',
  );
  assert.ok(existsSync(result.files.manifest));
  assert.ok(existsSync(result.files.readiness));
  assert.ok(existsSync(result.files.proofFacts));
  assert.ok(existsSync(result.files.publicOutput));
  assert.ok(existsSync(join(outDir, 'proof-run.json')));
  assert.ok(existsSync(join(outDir, 'prepared.json')));
  assert.ok(existsSync(join(outDir, 'proof.json')));
  assert.ok(existsSync(join(outDir, 'prove.log')));
  assert.ok(existsSync(join(outDir, 'verify.log')));

  const proofFacts = JSON.parse(readFileSync(result.files.proofFacts, 'utf8'));
  assert.equal(proofFacts.candidateProofFacts.schema, 'zkstark-amaci.native-stwo-handoff.v1.proof-facts');

  if (isIntegrityHashingAvailable()) {
    const expected = calculatePlainFactHash(0x1234n, [1n, 2n, 3n]);
    assert.deepEqual(proofFacts.candidateProofFacts.labels, [
      'program_hash',
      'public_output_hash',
      'program_output_fact_hash',
    ]);
    assert.deepEqual(proofFacts.candidateProofFacts.felts, [
      '0x1234',
      bigintToHex(expected.outputHash),
      bigintToHex(expected.factHash),
    ]);
  }
});

test('keeps native handoff blocked when program hash is missing', () => {
  const { proofRunJson } = setupProofRun();
  const report = analyzeNativeStwoHandoff(proofRunJson);

  assert.equal(report.localProofReady, true);
  assert.equal(report.nativeHandoffReady, false);
  assert.equal(report.candidateProofFacts.felts.length, 0);
  assert.ok(report.blockers.some((blocker) => /program hash/.test(blocker)));
});

test('keeps local proof blocked when scarb verify did not succeed', () => {
  const { proofRunJson } = setupProofRun({ verified: false });
  const report = analyzeNativeStwoHandoff(proofRunJson, {
    programHash: 0x1234n,
  });

  assert.equal(report.localProofReady, false);
  assert.equal(report.nativeHandoffReady, false);
  assert.ok(report.blockers.some((blocker) => /scarb verify/.test(blocker)));
});
