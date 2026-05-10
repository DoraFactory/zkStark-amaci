import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const runExecutionTests = process.env.RUN_CAIRO_EXECUTION_TESTS === '1';
const projectRoot = fileURLToPath(new URL('..', import.meta.url));

function runCircuit(circuit, options = {}) {
  const outDir = mkdtempSync(join(tmpdir(), `zkstark-amaci-${circuit}-execute-`));
  const result = spawnSync(
    process.execPath,
    [
      'tools/run-cairo-execute.mjs',
      '--circuit',
      circuit,
      '--out-dir',
      outDir,
      '--timeout-ms',
      '600000',
      ...(options.messageIndex === undefined ? [] : ['--message-index', String(options.messageIndex)]),
    ],
    {
      cwd: projectRoot,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 512,
    },
  );

  if (result.status !== 0) {
    process.stderr.write(result.stdout);
    process.stderr.write(result.stderr);
  }
  assert.equal(result.status, 0);
  const metadata = JSON.parse(result.stdout);
  assert.equal(metadata.status, 0);
  assert.equal(metadata.generatedInput, true);
  assert.ok(metadata.expectedPublicOutputFelts > 0);
  assert.match(readFileSync(metadata.stdoutPath, 'utf8'), /Program output|Run completed successfully/);
  return metadata;
}

test(
  'executes the small AddNewKey Cairo program with synthetic fixture args',
  { skip: !runExecutionTests, timeout: 600000 },
  () => {
    const metadata = runCircuit('add-new-key');
    assert.equal(metadata.executable, 'add_new_key');
  },
);

test(
  'executes deeply split ProcessMessages Cairo programs with synthetic fixture args',
  { skip: !runExecutionTests, timeout: 600000 },
  () => {
    const coordKey = runCircuit('process-message-coord-key');
    const ecdh = runCircuit('process-message-ecdh', { messageIndex: 3 });
    const signature = runCircuit('process-message-signature', { messageIndex: 3 });
    const core = runCircuit('process-message-step-core', { messageIndex: 3 });
    assert.equal(coordKey.executable, 'process_message_coord_key');
    assert.equal(ecdh.executable, 'process_message_ecdh');
    assert.equal(signature.executable, 'process_message_signature');
    assert.equal(core.executable, 'process_message_step_core');
  },
);

test(
  'executes the small ProcessMessages Cairo program with synthetic fixture args',
  { skip: !runExecutionTests, timeout: 600000 },
  () => {
    const metadata = runCircuit('process-messages');
    assert.equal(metadata.executable, 'process_messages_stateful_with_ecdh_signature');
  },
);

test(
  'executes the small ProcessDeactivateMessages Cairo program with synthetic fixture args',
  { skip: !runExecutionTests, timeout: 600000 },
  () => {
    const metadata = runCircuit('process-deactivate');
    assert.equal(metadata.executable, 'process_deactivate_messages_stateful');
  },
);

test(
  'executes deeply split ProcessDeactivateMessages Cairo programs with synthetic fixture args',
  { skip: !runExecutionTests, timeout: 600000 },
  () => {
    const coordKey = runCircuit('process-deactivate-coord-key');
    const commandEcdh = runCircuit('process-deactivate-ecdh-command', { messageIndex: 2 });
    const signature = runCircuit('process-deactivate-signature', { messageIndex: 2 });
    const currentDecrypt = runCircuit('process-deactivate-decrypt-current', { messageIndex: 2 });
    const newDecrypt = runCircuit('process-deactivate-decrypt-new', { messageIndex: 2 });
    const leafEcdh = runCircuit('process-deactivate-ecdh-leaf', { messageIndex: 2 });
    const core = runCircuit('process-deactivate-step-core', { messageIndex: 2 });
    assert.equal(coordKey.executable, 'process_deactivate_coord_key');
    assert.equal(commandEcdh.executable, 'process_deactivate_ecdh');
    assert.equal(signature.executable, 'process_deactivate_signature');
    assert.equal(currentDecrypt.executable, 'process_deactivate_decrypt');
    assert.equal(newDecrypt.executable, 'process_deactivate_decrypt');
    assert.equal(leafEcdh.executable, 'process_deactivate_ecdh');
    assert.equal(core.executable, 'process_deactivate_step_core');
  },
);
