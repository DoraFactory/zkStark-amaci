import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inspectStoneCairo1Fact } from '../src/integrity/stone-fact.mjs';
import { calculatePlainFactHash, poseidonManyFelts } from '../src/integrity/hashes.mjs';
import { bigintToHex } from '../src/compat/encoding.mjs';

test('extracts cairo1 program and output fact hashes from Stone proof public input', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-stone-fact-'));
  const proofPath = join(dir, 'stone-proof.json');
  const program = [11n, 12n, 13n];
  const output = [21n, 22n];
  const publicMemory = [...program, ...output].map((value, index) => ({
    address: index + 1,
    page: 0,
    value: bigintToHex(value),
  }));
  writeFileSync(
    proofPath,
    `${JSON.stringify({
      public_input: {
        layout: 'recursive_with_poseidon',
        n_steps: 131072,
        memory_segments: {
          output: { begin_addr: 100, stop_ptr: 102 },
        },
        public_memory: publicMemory,
      },
    })}\n`,
  );

  const result = inspectStoneCairo1Fact(proofPath);
  const expectedProgramHash = poseidonManyFelts(program);
  const expectedOutputHash = poseidonManyFelts(output);
  const expectedFact = calculatePlainFactHash(expectedProgramHash, output);

  assert.equal(result.programHash, bigintToHex(expectedProgramHash));
  assert.equal(result.outputHash, bigintToHex(expectedOutputHash));
  assert.equal(result.factHash, bigintToHex(expectedFact.factHash));
  assert.deepEqual(result.publicOutput.hexFelts, output.map(bigintToHex));
});
