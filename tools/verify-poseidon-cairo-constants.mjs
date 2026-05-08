#!/usr/bin/env node
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import assert from 'node:assert/strict';

const requireFromCircuits = createRequire(new URL('../../packages/circuits/package.json', import.meta.url));
const { C, M } = requireFromCircuits('circom/src/poseidon_constants.json');

function hex(value) {
  return `0x${BigInt(value).toString(16)}`;
}

function expectContains(source, value, label) {
  assert.match(source, new RegExp(`${label}: u32 = ${value};`.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
}

function expectValue(source, value, label) {
  assert.ok(source.includes(hex(value)), `${label} missing from generated Cairo constants`);
}

const inputPath = resolve(process.argv[2] ?? 'cairo/src/poseidon_constants.cairo');
const source = readFileSync(inputPath, 'utf8');

expectContains(source, C[1].length, 'POSEIDON_T3_ROUND_CONSTANTS');
expectContains(source, C[4].length, 'POSEIDON_T6_ROUND_CONSTANTS');
expectContains(source, M[1].length * M[1].length, 'POSEIDON_T3_MDS_VALUES');
expectContains(source, M[4].length * M[4].length, 'POSEIDON_T6_MDS_VALUES');

expectValue(source, C[1][0], 't3 first round constant');
expectValue(source, C[1].at(-1), 't3 last round constant');
expectValue(source, C[4][0], 't6 first round constant');
expectValue(source, C[4].at(-1), 't6 last round constant');
expectValue(source, M[1][0][0], 't3 first MDS value');
expectValue(source, M[1].at(-1).at(-1), 't3 last MDS value');
expectValue(source, M[4][0][0], 't6 first MDS value');
expectValue(source, M[4].at(-1).at(-1), 't6 last MDS value');

process.stdout.write(
  `${JSON.stringify(
    {
      inputPath,
      ok: true,
      t3RoundConstants: C[1].length,
      t6RoundConstants: C[4].length,
      t3MdsValues: M[1].length * M[1].length,
      t6MdsValues: M[4].length * M[4].length,
    },
    null,
    2,
  )}\n`,
);
