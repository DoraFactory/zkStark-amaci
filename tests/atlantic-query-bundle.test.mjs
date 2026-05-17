import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAtlanticQueryBundle } from '../src/atlantic/query-bundle.mjs';

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

test('exports Atlantic-compatible program and input files from a Stone AIR run', () => {
  const sourceDir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-atlantic-src-'));
  const program = join(sourceDir, 'program.sierra.json');
  const input = join(sourceDir, 'input.txt');
  const stoneAirRun = join(sourceDir, 'stone-air-run.json');
  writeJson(program, { sierra_program: ['0x1'], entry_points_by_type: {} });
  writeFileSync(input, '[1 2 3]\n');
  writeJson(stoneAirRun, {
    circuit: 'tally-native',
    stoneExecutable: 'tally_votes_native_stone',
    stoneTargetFunction: 'pkg::stone_entry::main',
    stoneExportFunction: 'pkg::stone_entry::main',
    stoneRunnerMainName: 'pkg::stone_entry::main',
    runnerSierraJson: program,
    cairo1ArgsTxt: input,
    layout: 'recursive_with_poseidon',
  });

  const outDir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-atlantic-out-'));
  const result = createAtlanticQueryBundle(stoneAirRun, outDir, {
    externalId: 'amaci-test',
    hints: 'herodotus_sn_grower',
  });

  assert.equal(result.manifest.schema, 'zkstark-amaci.atlantic-query-bundle.v1');
  assert.equal(result.manifest.status, 'atlantic_program_input_ready');
  assert.equal(result.manifest.fields.cairoVersion, 'cairo1');
  assert.equal(result.manifest.fields.cairoVm, 'rust');
  assert.equal(result.manifest.fields.result, 'PROOF_VERIFICATION_ON_L2');
  assert.equal(result.manifest.fields.sharpProver, 'stone');
  assert.equal(result.manifest.fields.layout, 'recursive_with_poseidon');
  assert.equal(result.manifest.fields.externalId, 'amaci-test');
  assert.equal(result.manifest.files.inputFile.feltCount, 3);
  assert.equal(result.manifest.files.inputFile.arrayWrapped, true);
  assert.deepEqual(result.manifest.warnings, []);
  assert.ok(existsSync(result.files.manifest));
  assert.ok(existsSync(result.files.submitScript));
  assert.ok(existsSync(result.files.programFile));
  assert.ok(existsSync(result.files.inputFile));

  const submitScript = readFileSync(result.files.submitScript, 'utf8');
  assert.match(submitScript, /atlantic\.api\.herodotus\.cloud\/atlantic-query/);
  assert.match(submitScript, /programFile=@/);
  assert.match(submitScript, /inputFile=@/);
  assert.match(submitScript, /result=PROOF_VERIFICATION_ON_L2/);
});

test('warns when the Cairo1 input file is not one array argument', () => {
  const sourceDir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-atlantic-flat-src-'));
  const program = join(sourceDir, 'program.sierra.json');
  const input = join(sourceDir, 'input.txt');
  const stoneAirRun = join(sourceDir, 'stone-air-run.json');
  writeJson(program, { sierra_program: ['0x1'], entry_points_by_type: {} });
  writeFileSync(input, '1 2 3\n');
  writeJson(stoneAirRun, {
    circuit: 'add-new-key-native',
    stoneExecutable: 'add_new_key_native_stone',
    runnerSierraJson: program,
    cairo1ArgsTxt: input,
    layout: 'recursive_with_poseidon',
  });

  const outDir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-atlantic-flat-out-'));
  const result = createAtlanticQueryBundle(stoneAirRun, outDir);

  assert.equal(result.manifest.files.inputFile.feltCount, 3);
  assert.equal(result.manifest.files.inputFile.arrayWrapped, false);
  assert.match(result.manifest.warnings[0], /not bracketed/);
});

