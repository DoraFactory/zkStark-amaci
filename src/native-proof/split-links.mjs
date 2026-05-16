import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

export const NATIVE_SPLIT_LINK_SCHEMA = 'zkstark-amaci.native-split-link-report.v1';

const BATCH_SIZE = 5;

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`failed to read ${label} JSON at ${path}: ${error.message}`);
  }
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function resolveFrom(baseJsonPath, maybePath) {
  if (typeof maybePath !== 'string' || maybePath.length === 0) {
    throw new Error(`missing path in ${baseJsonPath}`);
  }
  return resolve(dirname(baseJsonPath), maybePath);
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function collectFields(prepared) {
  return {
    ...(prepared.publicFields ?? {}),
    ...(prepared.cairoInput?.fields ?? {}),
    ...(prepared.cairoInput?.program_input?.fields ?? {}),
    ...(prepared.cairoInput?.publicFields ?? {}),
  };
}

function toBigInt(value, label) {
  if (typeof value === 'bigint') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new Error(`${label} must be an integer`);
    }
    return BigInt(value);
  }
  if (typeof value === 'string') {
    return BigInt(value);
  }
  if (value && typeof value === 'object') {
    if (hasOwn(value, 'value')) {
      return toBigInt(value.value, label);
    }
    if (hasOwn(value, 'low') && hasOwn(value, 'high')) {
      return toBigInt(value.low, `${label}.low`) + (toBigInt(value.high, `${label}.high`) << 128n);
    }
  }
  throw new Error(`${label} is not a bigint-compatible value`);
}

function formatValue(value) {
  return typeof value === 'bigint' ? value.toString() : String(value);
}

function loadProofRun(proofRunPath, role) {
  const absolutePath = resolve(proofRunPath);
  const proofRun = readJson(absolutePath, `${role} proof-run`);
  const preparedPath = resolveFrom(absolutePath, proofRun.preparedJson);
  const prepared = readJson(preparedPath, `${role} prepared`);
  return {
    role,
    path: absolutePath,
    proofRun,
    preparedPath,
    prepared,
    fields: collectFields(prepared),
  };
}

function getField(run, aliases) {
  const keys = Array.isArray(aliases) ? aliases : [aliases];
  for (const key of keys) {
    if (hasOwn(run.fields, key)) {
      return toBigInt(run.fields[key], `${run.role}.${key}`);
    }
  }
  throw new Error(`${run.role} is missing field ${keys.join('|')}`);
}

function addCheck(checks, name, fn) {
  try {
    const result = fn();
    if (result === false) {
      checks.push({ name, ok: false });
    }
  } catch (error) {
    checks.push({ name, ok: false, error: error.message });
  }
}

function expectOk(checks, name, condition, detail = {}) {
  checks.push({ name, ok: Boolean(condition), ...detail });
}

function expectEq(checks, name, actualFn, expectedFn, detail = {}) {
  addCheck(checks, name, () => {
    const actual = actualFn();
    const expected = expectedFn();
    const ok = actual === expected;
    checks.push({
      name,
      ok,
      actual: formatValue(actual),
      expected: formatValue(expected),
      ...detail,
    });
  });
}

function expectFieldEq(checks, name, leftRun, leftAliases, rightRun, rightAliases) {
  expectEq(
    checks,
    name,
    () => getField(leftRun, leftAliases),
    () => getField(rightRun, rightAliases),
    {
      actualField: `${leftRun.role}.${Array.isArray(leftAliases) ? leftAliases[0] : leftAliases}`,
      expectedField: `${rightRun.role}.${Array.isArray(rightAliases) ? rightAliases[0] : rightAliases}`,
    },
  );
}

function expectFieldPresent(checks, name, run, aliases) {
  addCheck(checks, name, () => {
    const value = getField(run, aliases);
    checks.push({
      name,
      ok: true,
      actual: formatValue(value),
      actualField: `${run.role}.${Array.isArray(aliases) ? aliases[0] : aliases}`,
    });
  });
}

function expectLiteral(checks, name, run, aliases, expected) {
  expectEq(
    checks,
    name,
    () => getField(run, aliases),
    () => BigInt(expected),
    {
      actualField: `${run.role}.${Array.isArray(aliases) ? aliases[0] : aliases}`,
    },
  );
}

function expectCircuit(checks, run, expectedCircuit) {
  const actual = run.proofRun.circuit ?? run.prepared.circuit;
  expectOk(checks, `${run.role} circuit is ${expectedCircuit}`, actual === expectedCircuit, {
    actual,
    expected: expectedCircuit,
  });
}

function loadManifestRun(manifestPath, path, role) {
  return loadProofRun(resolveFrom(manifestPath, path), role);
}

function loadManifestRunArray(manifestPath, manifest, key, expectedLength, checks) {
  const value = manifest[key];
  expectOk(checks, `${key} has ${expectedLength} proof runs`, Array.isArray(value) && value.length === expectedLength, {
    actual: Array.isArray(value) ? value.length : undefined,
    expected: expectedLength,
  });
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((path, index) => loadManifestRun(manifestPath, path, `${key}[${index}]`));
}

function summarizeProofRuns(runs) {
  return runs.map((run) => ({
    role: run.role,
    path: run.path,
    circuit: run.proofRun.circuit ?? run.prepared.circuit,
    executable: run.proofRun.executable ?? run.prepared.executable,
    executionId: run.proofRun.executionId,
    preparedJson: run.preparedPath,
  }));
}

function finalReport(kind, manifestPath, checks, runs, warnings) {
  const failed = checks.filter((check) => !check.ok);
  return {
    schema: NATIVE_SPLIT_LINK_SCHEMA,
    kind,
    manifestPath,
    ok: failed.length === 0,
    counts: {
      proofRuns: runs.length,
      checks: checks.length,
      failedChecks: failed.length,
    },
    proofRuns: summarizeProofRuns(runs),
    checks,
    warnings,
  };
}

function buildProcessMessagesReport(manifestPath, manifest) {
  const checks = [];
  const boundary = loadManifestRun(manifestPath, manifest.boundary, 'boundary');
  const coordKey = loadManifestRun(manifestPath, manifest.coordKey, 'coordKey');
  const ecdh = loadManifestRunArray(manifestPath, manifest, 'ecdh', BATCH_SIZE, checks);
  const signatures = loadManifestRunArray(manifestPath, manifest, 'signatures', BATCH_SIZE, checks);
  const cores = loadManifestRunArray(manifestPath, manifest, 'cores', BATCH_SIZE, checks);
  const runs = [boundary, coordKey, ...ecdh, ...signatures, ...cores];

  expectCircuit(checks, boundary, 'process-messages-boundary-native');
  expectCircuit(checks, coordKey, 'process-message-coord-key-native');
  ecdh.forEach((run) => expectCircuit(checks, run, 'process-message-ecdh-native'));
  signatures.forEach((run) => expectCircuit(checks, run, 'process-message-signature-native'));
  cores.forEach((run) => expectCircuit(checks, run, 'process-message-step-core-native'));

  expectFieldEq(
    checks,
    'boundary coord public key links to coord-key proof',
    boundary,
    ['coordPubKeyHash', 'coord_pub_key_hash'],
    coordKey,
    'coord_pub_key_hash',
  );
  expectFieldPresent(checks, 'coord-key binding is present', coordKey, 'coord_key_binding_hash');

  for (let index = 0; index < BATCH_SIZE; index += 1) {
    const ecdhRun = ecdh[index];
    const signatureRun = signatures[index];
    const coreRun = cores[index];
    if (!ecdhRun || !signatureRun || !coreRun) {
      continue;
    }

    expectLiteral(checks, `ecdh[${index}] message index`, ecdhRun, 'message_index', index);
    expectLiteral(checks, `signature[${index}] message index`, signatureRun, 'message_index', index);
    expectLiteral(checks, `core[${index}] message index`, coreRun, 'message_index', index);

    expectFieldEq(
      checks,
      `coord private key links coord-key to ecdh[${index}]`,
      coordKey,
      'coord_priv_key_hash',
      ecdhRun,
      'coord_priv_key_hash',
    );
    expectFieldEq(
      checks,
      `coord private key links coord-key to core[${index}]`,
      coordKey,
      'coord_priv_key_hash',
      coreRun,
      'coord_priv_key_hash',
    );
    expectFieldEq(checks, `ecdh[${index}] enc public key links to core`, ecdhRun, 'enc_pub_key_hash', coreRun, 'enc_pub_key_hash');
    expectFieldEq(checks, `ecdh[${index}] shared key links to core`, ecdhRun, 'shared_key_hash', coreRun, 'shared_key_hash');
    expectFieldEq(
      checks,
      `ecdh[${index}] shared key binding links to core`,
      ecdhRun,
      'shared_key_binding_hash',
      coreRun,
      'shared_key_binding_hash',
    );
    expectFieldEq(checks, `signature[${index}] public key links to core`, signatureRun, 'pub_key_hash', coreRun, 'signature_pub_key_hash');
    expectFieldEq(checks, `signature[${index}] r8 links to core`, signatureRun, 'r8_hash', coreRun, 'signature_r8_hash');
    expectFieldEq(
      checks,
      `signature[${index}] packed command links to core`,
      signatureRun,
      'packed_command_hash',
      coreRun,
      'packed_command_hash',
    );
    expectFieldEq(checks, `signature[${index}] s hash links to core`, signatureRun, 'cmd_sig_s_hash', coreRun, 'cmd_sig_s_hash');
    expectFieldEq(
      checks,
      `signature[${index}] command auth links to core`,
      signatureRun,
      'command_auth_hash',
      coreRun,
      'command_auth_hash',
    );
    expectFieldEq(
      checks,
      `signature[${index}] validity links to core`,
      signatureRun,
      'is_signature_valid',
      coreRun,
      'is_signature_valid',
    );

    expectFieldEq(
      checks,
      `core[${index}] packed vals links to boundary`,
      coreRun,
      'packed_vals_hash',
      boundary,
      ['packedVals', 'packed_vals'],
    );
    expectFieldEq(
      checks,
      `core[${index}] expected poll id links to boundary`,
      coreRun,
      'expected_poll_id',
      boundary,
      ['expectedPollId', 'expected_poll_id'],
    );
  }

  if (cores.length === BATCH_SIZE) {
    expectFieldEq(
      checks,
      'message hash chain starts at boundary batch start',
      cores[0],
      'previous_message_hash',
      boundary,
      ['batchStartHash', 'batch_start_hash'],
    );
    for (let index = 0; index < BATCH_SIZE; index += 1) {
      if (index === BATCH_SIZE - 1) {
        expectFieldEq(
          checks,
          'message hash chain ends at boundary batch end',
          cores[index],
          'next_message_hash',
          boundary,
          ['batchEndHash', 'batch_end_hash'],
        );
      } else {
        expectFieldEq(
          checks,
          `message hash chain links core[${index}] to core[${index + 1}]`,
          cores[index],
          'next_message_hash',
          cores[index + 1],
          'previous_message_hash',
        );
      }
    }

    expectFieldEq(
      checks,
      'state chain starts at boundary current commitment',
      cores[4],
      'current_state_commitment_hash',
      boundary,
      ['currentStateCommitment', 'current_state_commitment'],
    );
    expectFieldEq(
      checks,
      'state chain ends at boundary new commitment',
      cores[0],
      'new_state_commitment_hash',
      boundary,
      ['newStateCommitment', 'new_state_commitment'],
    );
    for (let index = BATCH_SIZE - 1; index > 0; index -= 1) {
      expectFieldEq(
        checks,
        `state root chain links core[${index}] to core[${index - 1}]`,
        cores[index],
        'new_state_root_hash',
        cores[index - 1],
        'current_state_root_hash',
      );
    }
    for (let index = 1; index < BATCH_SIZE; index += 1) {
      expectFieldEq(
        checks,
        `active state root is stable across core[0] and core[${index}]`,
        cores[0],
        'active_state_root_hash',
        cores[index],
        'active_state_root_hash',
      );
    }
  }

  return finalReport('processMessages', manifestPath, checks, runs, [
    'This report checks native split proof public-output links; it does not serialize or submit Starknet proof_facts.',
    'ProcessMessages boundary private roots and salts remain hidden behind public commitments; this report links commitments and the core state-root chain.',
  ]);
}

function buildProcessDeactivateReport(manifestPath, manifest) {
  const checks = [];
  const boundary = loadManifestRun(manifestPath, manifest.boundary, 'boundary');
  const coordKey = loadManifestRun(manifestPath, manifest.coordKey, 'coordKey');
  const commandEcdh = loadManifestRunArray(manifestPath, manifest, 'commandEcdh', BATCH_SIZE, checks);
  const signatures = loadManifestRunArray(manifestPath, manifest, 'signatures', BATCH_SIZE, checks);
  const currentDecrypt = loadManifestRunArray(manifestPath, manifest, 'currentDecrypt', BATCH_SIZE, checks);
  const newDecrypt = loadManifestRunArray(manifestPath, manifest, 'newDecrypt', BATCH_SIZE, checks);
  const leafEcdh = loadManifestRunArray(manifestPath, manifest, 'leafEcdh', BATCH_SIZE, checks);
  const cores = loadManifestRunArray(manifestPath, manifest, 'cores', BATCH_SIZE, checks);
  const runs = [boundary, coordKey, ...commandEcdh, ...signatures, ...currentDecrypt, ...newDecrypt, ...leafEcdh, ...cores];

  expectCircuit(checks, boundary, 'process-deactivate-boundary-native');
  expectCircuit(checks, coordKey, 'process-deactivate-coord-key-native');
  commandEcdh.forEach((run) => expectCircuit(checks, run, 'process-deactivate-ecdh-command-native'));
  signatures.forEach((run) => expectCircuit(checks, run, 'process-deactivate-signature-native'));
  currentDecrypt.forEach((run) => expectCircuit(checks, run, 'process-deactivate-decrypt-current-native'));
  newDecrypt.forEach((run) => expectCircuit(checks, run, 'process-deactivate-decrypt-new-native'));
  leafEcdh.forEach((run) => expectCircuit(checks, run, 'process-deactivate-ecdh-leaf-native'));
  cores.forEach((run) => expectCircuit(checks, run, 'process-deactivate-step-core-native'));

  expectFieldEq(
    checks,
    'boundary coord public key links to coord-key proof',
    boundary,
    ['coordPubKeyHash', 'coord_pub_key_hash'],
    coordKey,
    'coord_pub_key_hash',
  );
  expectFieldPresent(checks, 'coord-key binding is present', coordKey, 'coord_key_binding_hash');

  for (let index = 0; index < BATCH_SIZE; index += 1) {
    const commandRun = commandEcdh[index];
    const signatureRun = signatures[index];
    const currentDecryptRun = currentDecrypt[index];
    const newDecryptRun = newDecrypt[index];
    const leafRun = leafEcdh[index];
    const coreRun = cores[index];
    if (!commandRun || !signatureRun || !currentDecryptRun || !newDecryptRun || !leafRun || !coreRun) {
      continue;
    }

    expectLiteral(checks, `commandEcdh[${index}] message index`, commandRun, 'message_index', index);
    expectLiteral(checks, `commandEcdh[${index}] kind`, commandRun, 'ecdh_kind', 0);
    expectLiteral(checks, `signature[${index}] message index`, signatureRun, 'message_index', index);
    expectLiteral(checks, `currentDecrypt[${index}] message index`, currentDecryptRun, 'message_index', index);
    expectLiteral(checks, `currentDecrypt[${index}] kind`, currentDecryptRun, 'decrypt_kind', 0);
    expectLiteral(checks, `newDecrypt[${index}] message index`, newDecryptRun, 'message_index', index);
    expectLiteral(checks, `newDecrypt[${index}] kind`, newDecryptRun, 'decrypt_kind', 1);
    expectLiteral(checks, `leafEcdh[${index}] message index`, leafRun, 'message_index', index);
    expectLiteral(checks, `leafEcdh[${index}] kind`, leafRun, 'ecdh_kind', 1);
    expectLiteral(checks, `core[${index}] message index`, coreRun, 'message_index', index);

    for (const helperRun of [commandRun, currentDecryptRun, newDecryptRun, leafRun, coreRun]) {
      expectFieldEq(
        checks,
        `coord private key links coord-key to ${helperRun.role}`,
        coordKey,
        'coord_priv_key_hash',
        helperRun,
        'coord_priv_key_hash',
      );
    }

    expectFieldEq(checks, `commandEcdh[${index}] base links to core enc key`, commandRun, 'base_hash', coreRun, 'enc_pub_key_hash');
    expectFieldEq(
      checks,
      `commandEcdh[${index}] shared key links to core`,
      commandRun,
      'shared_key_hash',
      coreRun,
      'command_shared_key_hash',
    );
    expectFieldEq(
      checks,
      `commandEcdh[${index}] shared key binding links to core`,
      commandRun,
      'shared_key_binding_hash',
      coreRun,
      'command_shared_key_binding_hash',
    );
    expectFieldEq(checks, `leafEcdh[${index}] base links to core deactivate key`, leafRun, 'base_hash', coreRun, 'deactivate_pub_key_hash');
    expectFieldEq(
      checks,
      `leafEcdh[${index}] shared key links to core`,
      leafRun,
      'shared_key_hash',
      coreRun,
      'deactivate_shared_key_hash',
    );
    expectFieldEq(
      checks,
      `leafEcdh[${index}] shared key binding links to core`,
      leafRun,
      'shared_key_binding_hash',
      coreRun,
      'deactivate_shared_key_binding_hash',
    );
    expectFieldEq(checks, `signature[${index}] public key links to core`, signatureRun, 'pub_key_hash', coreRun, 'signature_pub_key_hash');
    expectFieldEq(checks, `signature[${index}] r8 links to core`, signatureRun, 'r8_hash', coreRun, 'signature_r8_hash');
    expectFieldEq(checks, `signature[${index}] packed command links to core`, signatureRun, 'packed_cmd_hash', coreRun, 'packed_cmd_hash');
    expectFieldEq(checks, `signature[${index}] s hash links to core`, signatureRun, 'cmd_sig_s_hash', coreRun, 'cmd_sig_s_hash');
    expectFieldEq(checks, `signature[${index}] command auth links to core`, signatureRun, 'command_auth_hash', coreRun, 'command_auth_hash');
    expectFieldEq(checks, `signature[${index}] validity links to core`, signatureRun, 'signature_valid', coreRun, 'signature_valid');
    expectFieldEq(
      checks,
      `currentDecrypt[${index}] c1 links to core`,
      currentDecryptRun,
      'c1_hash',
      coreRun,
      'current_state_ciphertext_c1_hash',
    );
    expectFieldEq(
      checks,
      `currentDecrypt[${index}] c2 links to core`,
      currentDecryptRun,
      'c2_hash',
      coreRun,
      'current_state_ciphertext_c2_hash',
    );
    expectFieldEq(
      checks,
      `currentDecrypt[${index}] odd flag links to core`,
      currentDecryptRun,
      'decrypt_is_odd',
      coreRun,
      'current_decrypt_is_odd',
    );
    expectFieldEq(
      checks,
      `currentDecrypt[${index}] decrypt binding links to core`,
      currentDecryptRun,
      'decrypt_binding_hash',
      coreRun,
      'current_decrypt_binding_hash',
    );
    expectFieldEq(
      checks,
      `newDecrypt[${index}] c1 links to core`,
      newDecryptRun,
      'c1_hash',
      coreRun,
      'new_state_ciphertext_c1_hash',
    );
    expectFieldEq(
      checks,
      `newDecrypt[${index}] c2 links to core`,
      newDecryptRun,
      'c2_hash',
      coreRun,
      'new_state_ciphertext_c2_hash',
    );
    expectFieldEq(
      checks,
      `newDecrypt[${index}] odd flag links to core`,
      newDecryptRun,
      'decrypt_is_odd',
      coreRun,
      'new_decrypt_is_odd',
    );
    expectFieldEq(
      checks,
      `newDecrypt[${index}] decrypt binding links to core`,
      newDecryptRun,
      'decrypt_binding_hash',
      coreRun,
      'new_decrypt_binding_hash',
    );
    expectFieldEq(
      checks,
      `core[${index}] expected poll id links to boundary`,
      coreRun,
      'expected_poll_id',
      boundary,
      ['expectedPollId', 'expected_poll_id'],
    );
    expectFieldEq(
      checks,
      `core[${index}] current state root links to boundary`,
      coreRun,
      'current_state_root_hash',
      boundary,
      ['currentStateRoot', 'current_state_root'],
    );
  }

  if (cores.length === BATCH_SIZE) {
    expectFieldEq(
      checks,
      'message hash chain starts at boundary batch start',
      cores[0],
      'previous_message_hash',
      boundary,
      ['batchStartHash', 'batch_start_hash'],
    );
    for (let index = 0; index < BATCH_SIZE; index += 1) {
      if (index === BATCH_SIZE - 1) {
        expectFieldEq(
          checks,
          'message hash chain ends at boundary batch end',
          cores[index],
          'next_message_hash',
          boundary,
          ['batchEndHash', 'batch_end_hash'],
        );
      } else {
        expectFieldEq(
          checks,
          `message hash chain links core[${index}] to core[${index + 1}]`,
          cores[index],
          'next_message_hash',
          cores[index + 1],
          'previous_message_hash',
        );
      }
    }

    expectFieldEq(
      checks,
      'deactivate chain starts at boundary current commitment',
      cores[0],
      'current_deactivate_commitment_hash',
      boundary,
      ['currentDeactivateCommitment', 'current_deactivate_commitment'],
    );
    expectFieldEq(
      checks,
      'deactivate chain ends at boundary new commitment',
      cores[4],
      'new_deactivate_commitment_hash',
      boundary,
      ['newDeactivateCommitment', 'new_deactivate_commitment'],
    );
    expectFieldEq(
      checks,
      'deactivate chain ends at boundary new deactivate root',
      cores[4],
      'new_deactivate_root_hash',
      boundary,
      ['newDeactivateRoot', 'new_deactivate_root'],
    );
    for (let index = 0; index < BATCH_SIZE - 1; index += 1) {
      expectFieldEq(
        checks,
        `active root chain links core[${index}] to core[${index + 1}]`,
        cores[index],
        'new_active_state_root_hash',
        cores[index + 1],
        'current_active_state_root_hash',
      );
      expectFieldEq(
        checks,
        `deactivate root chain links core[${index}] to core[${index + 1}]`,
        cores[index],
        'new_deactivate_root_hash',
        cores[index + 1],
        'current_deactivate_root_hash',
      );
      expectFieldEq(
        checks,
        `deactivate commitment chain links core[${index}] to core[${index + 1}]`,
        cores[index],
        'new_deactivate_commitment_hash',
        cores[index + 1],
        'current_deactivate_commitment_hash',
      );
      expectEq(
        checks,
        `deactivate index increments from core[${index}] to core[${index + 1}]`,
        () => getField(cores[index], 'deactivate_index') + 1n,
        () => getField(cores[index + 1], 'deactivate_index'),
      );
    }
  }

  return finalReport('processDeactivate', manifestPath, checks, runs, [
    'This report checks native split proof public-output links; it does not serialize or submit Starknet proof_facts.',
    'ProcessDeactivate boundary initial active/deactivate roots remain hidden behind the public current_deactivate_commitment; this report links the commitment and the core state-root chains.',
  ]);
}

export function createNativeSplitLinkReport(manifestPath, options = {}) {
  const absoluteManifestPath = resolve(manifestPath);
  const manifest = readJson(absoluteManifestPath, 'native split manifest');
  let report;
  if (Array.isArray(manifest.ecdh) && Array.isArray(manifest.cores)) {
    report = buildProcessMessagesReport(absoluteManifestPath, manifest);
  } else if (Array.isArray(manifest.commandEcdh) && Array.isArray(manifest.leafEcdh) && Array.isArray(manifest.cores)) {
    report = buildProcessDeactivateReport(absoluteManifestPath, manifest);
  } else {
    throw new Error(`unsupported native split manifest shape at ${absoluteManifestPath}`);
  }

  if (options.out) {
    writeJson(resolve(options.out), report);
  }
  return report;
}

export function formatNativeSplitLinkReport(report) {
  const failed = report.checks.filter((check) => !check.ok);
  const lines = [
    `Native split link report: ${report.kind}`,
    `  status: ${report.ok ? 'ok' : 'failed'}`,
    `  proofRuns: ${report.counts.proofRuns}`,
    `  checks: ${report.counts.checks - report.counts.failedChecks} passed, ${report.counts.failedChecks} failed`,
  ];

  if (failed.length > 0) {
    lines.push('', 'Failed checks:');
    for (const check of failed) {
      const detail = check.error
        ? ` error=${check.error}`
        : ` actual=${check.actual} expected=${check.expected}`;
      lines.push(`  - ${check.name}${detail}`);
    }
  }

  if (report.warnings.length > 0) {
    lines.push('', 'Warnings:');
    for (const warning of report.warnings) {
      lines.push(`  - ${warning}`);
    }
  }

  return `${lines.join('\n')}\n`;
}
