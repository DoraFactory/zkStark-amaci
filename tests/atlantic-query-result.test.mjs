import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fetchAtlanticQueryResult } from '../src/atlantic/query-result.mjs';

test('fetches Atlantic query status, writes summary, and downloads artifacts', async () => {
  const oldFetch = globalThis.fetch;
  const artifactBody = 'proof-data';
  globalThis.fetch = async (url) => {
    if (String(url).endsWith('/atlantic-query/query-1')) {
      return new Response(
        JSON.stringify({
          atlanticQuery: {
            id: 'query-1',
            transactionId: 'tx-1',
            status: 'DONE',
            step: 'PROOF_VERIFICATION',
            result: 'PROOF_VERIFICATION_ON_L2',
            network: 'TESTNET',
            chain: 'L2',
            sharpProver: 'stone',
            layout: 'recursive_with_poseidon',
            cairoVm: 'rust',
            cairoVersion: 'cairo1',
            declaredJobSize: 'S',
            jobSize: 'S',
            isFactMocked: false,
            isProofMocked: false,
            programHash: '0x123',
            integrityFactHash: '0x456',
            sharpFactHash: '0x789',
            createdAt: '2026-05-17T00:00:00.000Z',
            completedAt: '2026-05-17T00:01:00.000Z',
          },
          metadataUrls: ['https://storage.example/proof.json'],
        }),
        { status: 200 },
      );
    }
    if (String(url) === 'https://storage.example/proof.json') {
      return new Response(artifactBody, { status: 200 });
    }
    return new Response('not found', { status: 404 });
  };

  try {
    const outDir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-atlantic-result-'));
    const result = await fetchAtlanticQueryResult('query-1', outDir, {
      downloadArtifacts: true,
      apiKey: 'test-key',
    });

    assert.equal(result.summary.status, 'DONE');
    assert.equal(result.summary.integrityFactHash, '0x456');
    assert.equal(result.summary.metadataUrlCount, 1);
    assert.equal(result.artifacts.length, 1);
    assert.ok(existsSync(result.statusPath));
    assert.ok(existsSync(result.summaryPath));
    assert.ok(existsSync(result.resultPath));
    assert.equal(readFileSync(result.artifacts[0].path, 'utf8'), artifactBody);

    const summary = JSON.parse(readFileSync(result.summaryPath, 'utf8'));
    assert.equal(summary.programHash, '0x123');
  } finally {
    globalThis.fetch = oldFetch;
  }
});

