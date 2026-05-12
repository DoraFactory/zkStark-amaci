import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createProofArtifactInventory } from '../src/native-proof/inventory.mjs';

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function setupInventoryFixture({ includeExecutable = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-inventory-'));
  const proofRoot = join(dir, 'proof-root');
  const targetDev = join(dir, 'target-dev');
  const runDir = join(proofRoot, 'tally');
  const preparedJson = join(runDir, 'tally-prepared.json');
  const proofJson = join(runDir, 'proof.json');
  const proveLog = join(runDir, 'tally-prove.log');
  const verifyLog = join(runDir, 'tally-verify.log');
  const proofRunJson = join(runDir, 'proof-run.json');

  writeFileSync(join(dir, '.keep'), '');
  mkdirSync(runDir, { recursive: true });
  mkdirSync(targetDev, { recursive: true });
  writeJson(preparedJson, {
    publicOutput: {
      labels: ['magic', 'value'],
      felts: ['1', '2'],
    },
  });
  writeJson(proofJson, { proof: [] });
  writeFileSync(proveLog, 'proof generated\n');
  writeFileSync(verifyLog, 'Verified proof successfully\n');
  writeJson(proofRunJson, {
    circuit: 'tally',
    executable: 'tally_votes',
    executionId: '7',
    proofProducer: 'scarb-stwo-local',
    proofJson,
    preparedJson,
    proveLog,
    verifyLog,
  });

  if (includeExecutable) {
    writeJson(join(targetDev, 'tally_votes.executable.json'), {
      program: {
        bytecode: ['0x1', '0x2', '0x3'],
      },
      entrypoints: {
        EXTERNAL: [{ selector: '0x1' }],
      },
    });
  }

  return { proofRoot, targetDev };
}

test('exports a complete inventory for verified proof runs and executable artifacts', () => {
  const { proofRoot, targetDev } = setupInventoryFixture();
  const out = join(proofRoot, 'inventory.json');
  const inventory = createProofArtifactInventory(proofRoot, {
    targetDevDir: targetDev,
    out,
  });

  assert.equal(inventory.schema, 'zkstark-amaci.proof-artifact-inventory.v1');
  assert.equal(inventory.status, 'complete_local_inventory');
  assert.equal(inventory.counts.proofRuns, 1);
  assert.equal(inventory.counts.verifiedProofRuns, 1);
  assert.equal(inventory.counts.uniqueExecutables, 1);
  assert.equal(inventory.counts.blockers, 0);
  assert.equal(inventory.executables[0].executable, 'tally_votes');
  assert.equal(inventory.executables[0].programBytecodeLength, 3);
  assert.match(inventory.executables[0].localProgramDigest, /^0x[0-9a-f]+$/);
  assert.ok(existsSync(out));

  const written = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(written.status, 'complete_local_inventory');
});

test('reports missing executable artifacts as blockers', () => {
  const { proofRoot, targetDev } = setupInventoryFixture({ includeExecutable: false });
  const inventory = createProofArtifactInventory(proofRoot, {
    targetDevDir: targetDev,
  });

  assert.equal(inventory.status, 'incomplete_local_inventory');
  assert.equal(inventory.counts.proofRuns, 1);
  assert.equal(inventory.counts.verifiedProofRuns, 0);
  assert.equal(inventory.counts.blockers, 1);
  assert.ok(inventory.proofRuns[0].blockers.some((blocker) => /executable/.test(blocker)));
});
