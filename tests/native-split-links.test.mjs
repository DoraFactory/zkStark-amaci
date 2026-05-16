import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { buildSmallSyntheticFixture } from '../src/fixtures/small-amaci-fixtures.mjs';
import {
  buildNativeCairoProcessMessageCoordKeyInput,
  buildNativeCairoProcessMessageDecryptInput,
  buildNativeCairoProcessMessageEcdhInput,
  buildNativeCairoProcessMessageSignatureInput,
  buildNativeCairoProcessMessageStepCoreInput,
} from '../src/msg/cairo-input.mjs';
import { buildNativeCairoProcessMessagesBoundaryInput } from '../src/msg/native-cairo-input.mjs';
import { evaluateNativeProcessMessagesBoundary } from '../src/msg/native-process-messages.mjs';
import { evaluateProcessMessagesStateful } from '../src/msg/process-messages.mjs';
import {
  buildNativeCairoProcessDeactivateCoordKeyInput,
  buildNativeCairoProcessDeactivateDecryptInput,
  buildNativeCairoProcessDeactivateEcdhInput,
  buildNativeCairoProcessDeactivateSignatureInput,
  buildNativeCairoProcessDeactivateStepCoreInput,
} from '../src/deactivate/cairo-input.mjs';
import { buildNativeCairoProcessDeactivateBoundaryInput } from '../src/deactivate/native-cairo-input.mjs';
import { evaluateNativeProcessDeactivateMessagesBoundary } from '../src/deactivate/native-process-deactivate-messages.mjs';
import { evaluateProcessDeactivateMessagesStateful } from '../src/deactivate/process-deactivate-messages.mjs';
import { createNativeSplitLinkReport } from '../src/native-proof/split-links.mjs';

function serialize(value) {
  return JSON.stringify(
    value,
    (_key, inner) => (typeof inner === 'bigint' ? inner.toString() : inner),
    2,
  );
}

function writeJson(path, value) {
  writeFileSync(path, `${serialize(value)}\n`);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function tempRoot(label) {
  return mkdtempSync(join(tmpdir(), `zkstark-amaci-${label}-`));
}

function writePreparedRun(root, role, circuit, cairoInput, publicFields) {
  const dir = join(root, role.replaceAll(/[^\w.-]/g, '-'));
  mkdirSync(dir, { recursive: true });
  const preparedJson = join(dir, `${role}.prepared.json`);
  const proofRunJson = join(dir, 'proof-run.json');
  writeJson(preparedJson, {
    circuit,
    executable: circuit,
    publicFields,
    publicOutput: {
      labels: cairoInput.public_output_labels ?? [],
      felts: cairoInput.public_output ?? [],
    },
    cairoInput,
  });
  writeJson(proofRunJson, {
    circuit,
    executable: circuit,
    proofProducer: 'test',
    preparedJson,
  });
  return proofRunJson;
}

function writeProcessMessagesManifest(root) {
  const input = buildSmallSyntheticFixture('process-messages');
  const stateful = evaluateProcessMessagesStateful(input);
  const boundary = evaluateNativeProcessMessagesBoundary(input);

  const manifest = {
    boundary: writePreparedRun(
      root,
      'boundary',
      'process-messages-boundary-native',
      buildNativeCairoProcessMessagesBoundaryInput(input, boundary),
      boundary.publicFields,
    ),
    coordKey: writePreparedRun(
      root,
      'coord-key',
      'process-message-coord-key-native',
      buildNativeCairoProcessMessageCoordKeyInput(input, stateful),
      stateful.publicFields,
    ),
    ecdh: [],
    decrypt: [],
    signatures: [],
    cores: [],
  };

  for (let index = 0; index < 5; index += 1) {
    manifest.ecdh.push(writePreparedRun(
      root,
      `ecdh-${index}`,
      'process-message-ecdh-native',
      buildNativeCairoProcessMessageEcdhInput(input, index, stateful),
      stateful.publicFields,
    ));
    manifest.decrypt.push(writePreparedRun(
      root,
      `decrypt-${index}`,
      'process-message-decrypt-native',
      buildNativeCairoProcessMessageDecryptInput(input, index, stateful),
      stateful.publicFields,
    ));
    manifest.signatures.push(writePreparedRun(
      root,
      `signature-${index}`,
      'process-message-signature-native',
      buildNativeCairoProcessMessageSignatureInput(input, index, stateful),
      stateful.publicFields,
    ));
    manifest.cores.push(writePreparedRun(
      root,
      `core-${index}`,
      'process-message-step-core-native',
      buildNativeCairoProcessMessageStepCoreInput(input, index, stateful),
      stateful.publicFields,
    ));
  }

  const manifestPath = join(root, 'split-process-messages-native-proofs.json');
  writeJson(manifestPath, manifest);
  return { manifestPath, manifest };
}

function writeProcessDeactivateManifest(root) {
  const input = buildSmallSyntheticFixture('process-deactivate');
  const stateful = evaluateProcessDeactivateMessagesStateful(input);
  const boundary = evaluateNativeProcessDeactivateMessagesBoundary(input);

  const manifest = {
    boundary: writePreparedRun(
      root,
      'boundary',
      'process-deactivate-boundary-native',
      buildNativeCairoProcessDeactivateBoundaryInput(input, boundary),
      boundary.publicFields,
    ),
    coordKey: writePreparedRun(
      root,
      'coord-key',
      'process-deactivate-coord-key-native',
      buildNativeCairoProcessDeactivateCoordKeyInput(input, stateful),
      stateful.publicFields,
    ),
    commandEcdh: [],
    signatures: [],
    currentDecrypt: [],
    newDecrypt: [],
    leafEcdh: [],
    cores: [],
  };

  for (let index = 0; index < 5; index += 1) {
    manifest.commandEcdh.push(writePreparedRun(
      root,
      `command-ecdh-${index}`,
      'process-deactivate-ecdh-command-native',
      buildNativeCairoProcessDeactivateEcdhInput(input, index, 'command', stateful),
      stateful.publicFields,
    ));
    manifest.signatures.push(writePreparedRun(
      root,
      `signature-${index}`,
      'process-deactivate-signature-native',
      buildNativeCairoProcessDeactivateSignatureInput(input, index, stateful),
      stateful.publicFields,
    ));
    manifest.currentDecrypt.push(writePreparedRun(
      root,
      `current-decrypt-${index}`,
      'process-deactivate-decrypt-current-native',
      buildNativeCairoProcessDeactivateDecryptInput(input, index, 'current', stateful),
      stateful.publicFields,
    ));
    manifest.newDecrypt.push(writePreparedRun(
      root,
      `new-decrypt-${index}`,
      'process-deactivate-decrypt-new-native',
      buildNativeCairoProcessDeactivateDecryptInput(input, index, 'new', stateful),
      stateful.publicFields,
    ));
    manifest.leafEcdh.push(writePreparedRun(
      root,
      `leaf-ecdh-${index}`,
      'process-deactivate-ecdh-leaf-native',
      buildNativeCairoProcessDeactivateEcdhInput(input, index, 'leaf', stateful),
      stateful.publicFields,
    ));
    manifest.cores.push(writePreparedRun(
      root,
      `core-${index}`,
      'process-deactivate-step-core-native',
      buildNativeCairoProcessDeactivateStepCoreInput(input, index, stateful),
      stateful.publicFields,
    ));
  }

  const manifestPath = join(root, 'split-process-deactivate-native-proofs.json');
  writeJson(manifestPath, manifest);
  return { manifestPath, manifest };
}

function tamperRunField(proofRunPath, fieldName) {
  const proofRun = readJson(proofRunPath);
  const prepared = readJson(proofRun.preparedJson);
  const current = BigInt(prepared.cairoInput.publicFields[fieldName]);
  prepared.cairoInput.publicFields[fieldName] = (current + 1n).toString();
  writeJson(proofRun.preparedJson, prepared);
}

test('validates native ProcessMessages split proof links and detects tampering', () => {
  const { manifestPath, manifest } = writeProcessMessagesManifest(tempRoot('messages-links'));
  const report = createNativeSplitLinkReport(manifestPath);
  assert.equal(report.ok, true, report.checks.filter((check) => !check.ok).map((check) => check.name).join('\n'));
  assert.equal(report.kind, 'processMessages');
  assert.equal(report.counts.proofRuns, 22);
  assert.equal(report.counts.failedChecks, 0);

  tamperRunField(manifest.ecdh[2], 'shared_key_hash');
  const tampered = createNativeSplitLinkReport(manifestPath);
  assert.equal(tampered.ok, false);
  assert.ok(tampered.checks.some((check) => !check.ok && check.name === 'ecdh[2] shared key links to core'));
});

test('validates native ProcessDeactivate split proof links and detects tampering', () => {
  const { manifestPath, manifest } = writeProcessDeactivateManifest(tempRoot('deactivate-links'));
  const report = createNativeSplitLinkReport(manifestPath);
  assert.equal(report.ok, true, report.checks.filter((check) => !check.ok).map((check) => check.name).join('\n'));
  assert.equal(report.kind, 'processDeactivate');
  assert.equal(report.counts.proofRuns, 32);
  assert.equal(report.counts.failedChecks, 0);

  tamperRunField(manifest.currentDecrypt[3], 'c1_hash');
  const tampered = createNativeSplitLinkReport(manifestPath);
  assert.equal(tampered.ok, false);
  assert.ok(tampered.checks.some((check) => !check.ok && check.name === 'currentDecrypt[3] c1 links to core'));
});
