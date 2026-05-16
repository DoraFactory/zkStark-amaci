import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildIntegrityCalldataPackage,
  parseIntegrityCalldata,
} from '../src/integrity/calldata.mjs';
import { buildIntegritySplitCalldataPackage } from '../src/integrity/split-calldata.mjs';

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

test('parses raw Integrity calldata felt lists', () => {
  assert.deepEqual(parseIntegrityCalldata('1 0x2\n3,4\n# comment\n5'), [
    '1',
    '0x2',
    '3',
    '4',
    '5',
  ]);
});

test('parses JSON Integrity calldata wrappers', () => {
  assert.deepEqual(parseIntegrityCalldata(JSON.stringify({ calldata: ['0x1', 2, '3'] })), [
    '0x1',
    '2',
    '3',
  ]);
});

test('rejects malformed Integrity calldata values', () => {
  assert.throws(() => parseIntegrityCalldata(JSON.stringify({ calldata: ['0x1', 'bad'] })));
});

test('wraps existing raw calldata into standard JSON package', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-calldata-'));
  const rawCalldata = join(dir, 'calldata');
  const out = join(dir, 'integrity-calldata.json');
  writeFileSync(rawCalldata, '1\n0x2\n3\n');

  const result = buildIntegrityCalldataPackage({
    rawCalldataPath: rawCalldata,
    out,
  });

  assert.equal(result.calldataFelts, 3);
  assert.equal(existsSync(out), true);
  const parsed = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(parsed.schema, 'zkstark-amaci.integrity-calldata.v1');
  assert.equal(parsed.proofProducer, 'stone');
  assert.deepEqual(parsed.calldata, ['1', '0x2', '3']);
});

test('runs a proof_serializer-compatible binary and writes calldata JSON', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-serializer-'));
  const fakeSerializer = join(dir, 'proof_serializer');
  const stoneProof = join(dir, 'stone-proof.json');
  const out = join(dir, 'integrity-calldata.json');
  writeFileSync(stoneProof, '{"proof":[]}\n');
  writeFileSync(fakeSerializer, '#!/usr/bin/env sh\ncat >/dev/null\nprintf "7 0x8 9\\n"\n');
  chmodSync(fakeSerializer, 0o755);

  const result = buildIntegrityCalldataPackage({
    stoneProofPath: stoneProof,
    proofSerializer: fakeSerializer,
    out,
  });

  assert.equal(result.calldataFelts, 3);
  const parsed = JSON.parse(readFileSync(out, 'utf8'));
  assert.deepEqual(parsed.calldata, ['7', '0x8', '9']);
  assert.equal(parsed.source.stoneProof.exists, true);
});

test('wraps split Integrity calldata into standard JSON package', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-split-calldata-'));
  writeFileSync(join(dir, 'initial'), '1 2 3\n');
  writeFileSync(join(dir, 'step1'), '4 5\n');
  writeFileSync(join(dir, 'final'), '6 7\n');
  const out = join(dir, 'integrity-split-calldata.json');

  const result = buildIntegritySplitCalldataPackage({
    splitCalldataDir: dir,
    out,
  });

  assert.equal(result.calldataFelts, 7);
  assert.equal(result.stepCount, 1);
  const parsed = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(parsed.schema, 'zkstark-amaci.integrity-split-calldata.v1');
  assert.equal(parsed.serializationType, 'split');
  assert.equal(parsed.files.initial.feltCount, 3);
  assert.equal(parsed.files.steps[0].feltCount, 2);
  assert.equal(parsed.files.final.feltCount, 2);
  assert.ok(parsed.settings.verifierConfigHash);
});
