import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  convertScarbArgsJsonFile,
  formatCairo1RunArgs,
  parseScarbArgsJson,
} from '../src/cairo-run-args.mjs';

test('formats cairo1-run proof-mode args as one felt array', () => {
  assert.equal(formatCairo1RunArgs(['0x1', '2', '0xabc']), '[0x1 2 0xabc]\n');
});

test('formats flat cairo1-run args when requested', () => {
  assert.equal(formatCairo1RunArgs(['0x1', '2'], { array: false }), '0x1 2\n');
});

test('parses Scarb executable args JSON felts', () => {
  assert.deepEqual(parseScarbArgsJson('["0x1", "2", 3]'), ['0x1', '2', '3']);
});

test('rejects malformed Scarb executable args JSON values', () => {
  assert.throws(() => parseScarbArgsJson('{"arg":"0x1"}'), /must be an array/);
  assert.throws(() => parseScarbArgsJson('["0x1", "-2"]'), /not a felt literal/);
});

test('converts Scarb args JSON file to cairo1-run args file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-cairo1-args-'));
  const input = join(dir, 'args.json');
  const output = join(dir, 'args.txt');
  writeFileSync(input, `${JSON.stringify(['0x1', '2', '0x3'])}\n`);

  const result = convertScarbArgsJsonFile(input, output);

  assert.equal(result.feltCount, 3);
  assert.equal(result.arrayWrapped, true);
  assert.equal(readFileSync(output, 'utf8'), '[0x1 2 0x3]\n');
});
