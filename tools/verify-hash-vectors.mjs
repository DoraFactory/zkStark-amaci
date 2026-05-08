#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyHashVectors } from '../src/hash-vector-check.mjs';

function usage() {
  return `Usage:
  node tools/verify-hash-vectors.mjs <hash-vectors.json>
`;
}

const inputPath = process.argv[2];
if (!inputPath || inputPath === '--help' || inputPath === '-h') {
  console.log(usage());
  process.exit(inputPath ? 0 : 1);
}

const payload = JSON.parse(readFileSync(resolve(inputPath), 'utf8'));
const vectors = Array.isArray(payload) ? payload : payload.vectors;
const results = verifyHashVectors(vectors);

process.stdout.write(
  `${JSON.stringify(
    {
      inputPath: resolve(inputPath),
      vectorCount: results.length,
      ok: true,
    },
    null,
    2,
  )}\n`,
);
