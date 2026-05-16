import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildIntegritySplitCalldataPackage } from '../src/integrity/split-calldata.mjs';
import { submitIntegritySplitProof } from '../src/integrity/submission.mjs';

test('builds dry-run sncast calls for split Integrity submission', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-submit-'));
  writeFileSync(join(dir, 'initial'), '1 2\n');
  writeFileSync(join(dir, 'step1'), '3\n');
  writeFileSync(join(dir, 'final'), '4 5\n');
  const splitPackage = join(dir, 'integrity-split-calldata.json');
  buildIntegritySplitCalldataPackage({
    splitCalldataDir: dir,
    out: splitPackage,
  });

  const result = submitIntegritySplitProof({
    splitCalldata: splitPackage,
    jobId: 77,
    send: false,
    expectedFact: { factHash: '0x1234' },
  });

  assert.equal(result.status, 'dry_run');
  assert.equal(result.plan.network, 'sepolia');
  assert.equal(result.plan.transactionCount, 3);
  assert.equal(result.plan.transactions[0].functionName, 'verify_proof_initial');
  assert.equal(result.plan.transactions[1].functionName, 'verify_proof_step');
  assert.equal(result.plan.transactions[2].functionName, 'verify_proof_final_and_register_fact');
  assert.equal(result.plan.transactions[0].calldata[0], '0x4d');
  assert.equal(result.expectedFact.factHash, '0x1234');
});
