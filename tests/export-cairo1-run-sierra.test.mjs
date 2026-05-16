import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import assert from 'node:assert/strict';

test('exports one cairo1-run main and hides package mains', () => {
  const dir = mkdtempSync(join(tmpdir(), 'export-cairo1-run-sierra-'));
  const input = join(dir, 'package.sierra.json');
  const output = join(dir, 'runner.sierra.json');

  writeFileSync(
    input,
    `${JSON.stringify({
      funcs: [
        { id: { debug_name: 'pkg::native_tally_votes::main' } },
        { id: { debug_name: 'pkg::stone_tally_votes::tally_votes_stone_main' } },
        { id: { debug_name: 'pkg::tally_votes::main' } },
        { id: { debug_name: 'pkg::helper' } },
      ],
    })}\n`,
  );

  const result = spawnSync(
    process.execPath,
    [
      'tools/export-cairo1-run-sierra.mjs',
      input,
      '--function',
      'pkg::stone_tally_votes::tally_votes_stone_main',
      '--main-name',
      'pkg::stone_tally_votes::main',
      '--out',
      output,
    ],
    { cwd: process.cwd(), encoding: 'utf8' },
  );

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /hidden package main functions: 2/);

  const exported = JSON.parse(readFileSync(output, 'utf8'));
  const debugNames = exported.funcs.map((fn) => fn.id.debug_name);

  assert.deepEqual(
    debugNames.filter((debugName) => debugName.endsWith('::main')),
    ['pkg::stone_tally_votes::main'],
  );
  assert.ok(debugNames.includes('pkg::native_tally_votes::__cairo1_run_hidden_main'));
  assert.ok(debugNames.includes('pkg::tally_votes::__cairo1_run_hidden_main'));
  assert.ok(debugNames.includes('pkg::helper'));
});
