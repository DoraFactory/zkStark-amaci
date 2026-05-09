#!/usr/bin/env node
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import assert from 'node:assert/strict';

function parseCairoMatchConstants(source, functionName, expected) {
  const start = source.indexOf(`pub fn ${functionName}`);
  if (start === -1) {
    throw new Error(`missing ${functionName} in Cairo Poseidon constants`);
  }
  const nextFunction = source.indexOf('\npub fn ', start + 1);
  const block = source.slice(start, nextFunction === -1 ? source.length : nextFunction);
  const values = [...block.matchAll(/\b\d+\s*=>\s*(0x[0-9a-f]+)/g)].map((match) => BigInt(match[1]));
  if (values.length !== expected) {
    throw new Error(`${functionName} expected ${expected} constants, found ${values.length}`);
  }
  return values;
}

function chunkMatrix(values, width) {
  const rows = [];
  for (let i = 0; i < values.length; i += width) {
    rows.push(values.slice(i, i + width));
  }
  return rows;
}

function loadExpectedConstants(source) {
  try {
    const requireFromLocal = createRequire(new URL('../package.json', import.meta.url));
    const { C, M } = requireFromLocal('circom/src/poseidon_constants.json');
    return { C, M };
  } catch {
    const c3 = parseCairoMatchConstants(source, 'poseidon_t3_c', 195);
    const c4 = parseCairoMatchConstants(source, 'poseidon_t4_c', 256);
    const c6 = parseCairoMatchConstants(source, 'poseidon_t6_c', 408);
    const m3 = parseCairoMatchConstants(source, 'poseidon_t3_m', 9);
    const m4 = parseCairoMatchConstants(source, 'poseidon_t4_m', 16);
    const m6 = parseCairoMatchConstants(source, 'poseidon_t6_m', 36);
    return {
      C: [[], c3, c4, [], c6],
      M: [[], chunkMatrix(m3, 3), chunkMatrix(m4, 4), [], chunkMatrix(m6, 6)],
    };
  }
}

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
const { C, M } = loadExpectedConstants(source);

expectContains(source, C[1].length, 'POSEIDON_T3_ROUND_CONSTANTS');
expectContains(source, C[2].length, 'POSEIDON_T4_ROUND_CONSTANTS');
expectContains(source, C[4].length, 'POSEIDON_T6_ROUND_CONSTANTS');
expectContains(source, M[1].length * M[1].length, 'POSEIDON_T3_MDS_VALUES');
expectContains(source, M[2].length * M[2].length, 'POSEIDON_T4_MDS_VALUES');
expectContains(source, M[4].length * M[4].length, 'POSEIDON_T6_MDS_VALUES');

expectValue(source, C[1][0], 't3 first round constant');
expectValue(source, C[1].at(-1), 't3 last round constant');
expectValue(source, C[2][0], 't4 first round constant');
expectValue(source, C[2].at(-1), 't4 last round constant');
expectValue(source, C[4][0], 't6 first round constant');
expectValue(source, C[4].at(-1), 't6 last round constant');
expectValue(source, M[1][0][0], 't3 first MDS value');
expectValue(source, M[1].at(-1).at(-1), 't3 last MDS value');
expectValue(source, M[2][0][0], 't4 first MDS value');
expectValue(source, M[2].at(-1).at(-1), 't4 last MDS value');
expectValue(source, M[4][0][0], 't6 first MDS value');
expectValue(source, M[4].at(-1).at(-1), 't6 last MDS value');

process.stdout.write(
  `${JSON.stringify(
    {
      inputPath,
      ok: true,
      t3RoundConstants: C[1].length,
      t4RoundConstants: C[2].length,
      t6RoundConstants: C[4].length,
      t3MdsValues: M[1].length * M[1].length,
      t4MdsValues: M[2].length * M[2].length,
      t6MdsValues: M[4].length * M[4].length,
    },
    null,
    2,
  )}\n`,
);
