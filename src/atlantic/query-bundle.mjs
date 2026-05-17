import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, dirname, join, resolve } from 'node:path';

const ATLANTIC_QUERY_ENDPOINT = 'https://atlantic.api.herodotus.cloud/atlantic-query';

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function ensureFile(path, label) {
  if (!path || !existsSync(path) || !statSync(path).isFile()) {
    throw new Error(`missing ${label}: ${path ?? '<unset>'}`);
  }
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function fileInfo(path) {
  return {
    path,
    bytes: statSync(path).size,
    sha256: `0x${sha256File(path)}`,
  };
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function parseInputShape(inputText) {
  const trimmed = inputText.trim();
  const arrayWrapped = trimmed.startsWith('[') && trimmed.endsWith(']');
  const feltMatches = trimmed.match(/0x[0-9a-fA-F]+|-?\d+/g) ?? [];
  return {
    arrayWrapped,
    feltCount: feltMatches.length,
  };
}

function copyArtifact(source, outDir, name) {
  const destination = resolve(outDir, name);
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(source, destination);
  return destination;
}

function buildCurlScript(manifest) {
  const forms = [
    ['declaredJobSize', manifest.fields.declaredJobSize],
    ['externalId', manifest.fields.externalId],
    ['sharpProver', manifest.fields.sharpProver],
    ['layout', manifest.fields.layout],
    ['cairoVm', manifest.fields.cairoVm],
    ['cairoVersion', manifest.fields.cairoVersion],
    ['result', manifest.fields.result],
    ['mockFactHash', manifest.fields.mockFactHash],
    ['network', manifest.fields.network],
    ['programHash', manifest.fields.programHash],
  ];
  if (manifest.fields.dedupId !== null && manifest.fields.dedupId !== undefined) {
    forms.push(['dedupId', manifest.fields.dedupId]);
  }
  if (manifest.fields.hints) {
    forms.push(['hints', manifest.fields.hints]);
  }
  forms.push(['programFile', `@${manifest.files.programFile.path}`]);
  forms.push(['inputFile', `@${manifest.files.inputFile.path}`]);

  const lines = [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    ': "${ATLANTIC_API_KEY:?set ATLANTIC_API_KEY from the Herodotus console}"',
    '',
    'curl --request POST \\',
    `  --url ${shellQuote(manifest.endpoint)} \\`,
    '  --header "api-key: ${ATLANTIC_API_KEY}" \\',
  ];

  forms.forEach(([key, value], index) => {
    const suffix = index === forms.length - 1 ? '' : ' \\';
    lines.push(`  --form ${shellQuote(`${key}=${value}`)}${suffix}`);
  });

  lines.push('');
  return `${lines.join('\n')}\n`;
}

export function createAtlanticQueryBundle(stoneAirRunPath, outDir, options = {}) {
  const absoluteStoneAirRunPath = resolve(stoneAirRunPath);
  const absoluteOutDir = resolve(outDir);
  ensureFile(absoluteStoneAirRunPath, 'Stone AIR run metadata');

  const stoneAirRun = readJson(absoluteStoneAirRunPath);
  const programSource = resolve(stoneAirRun.runnerSierraJson ?? '');
  const inputSource = resolve(stoneAirRun.cairo1ArgsTxt ?? '');
  ensureFile(programSource, 'Atlantic programFile source');
  ensureFile(inputSource, 'Atlantic inputFile source');

  mkdirSync(absoluteOutDir, { recursive: true });
  const programFile = copyArtifact(
    programSource,
    absoluteOutDir,
    options.programFilename ?? `${stoneAirRun.stoneExecutable ?? 'program'}.program.sierra.json`,
  );
  const inputFile = copyArtifact(
    inputSource,
    absoluteOutDir,
    options.inputFilename ?? `${stoneAirRun.stoneExecutable ?? 'program'}.input.txt`,
  );
  const metadataFile = copyArtifact(absoluteStoneAirRunPath, absoluteOutDir, 'stone-air-run.json');

  const inputShape = parseInputShape(readFileSync(inputFile, 'utf8'));
  const warnings = [];
  if (!inputShape.arrayWrapped) {
    warnings.push(
      'inputFile is not bracketed as one Array<felt252>; Atlantic Cairo1 docs expect this shape for main(input: Array<felt252>)',
    );
  }

  const fields = {
    declaredJobSize: options.declaredJobSize ?? 'S',
    externalId: options.externalId ?? '',
    dedupId: options.dedupId ?? null,
    sharpProver: options.sharpProver ?? 'stone',
    layout: options.layout ?? stoneAirRun.layout ?? 'recursive_with_poseidon',
    cairoVm: options.cairoVm ?? 'rust',
    cairoVersion: options.cairoVersion ?? 'cairo1',
    result: options.result ?? 'PROOF_VERIFICATION_ON_L2',
    mockFactHash: options.mockFactHash ?? 'false',
    network: options.network ?? 'TESTNET',
    hints: options.hints,
    programHash: options.programHash ?? '',
  };

  const manifest = {
    schema: 'zkstark-amaci.atlantic-query-bundle.v1',
    status: 'atlantic_program_input_ready',
    endpoint: ATLANTIC_QUERY_ENDPOINT,
    source: {
      stoneAirRun: absoluteStoneAirRunPath,
      circuit: stoneAirRun.circuit,
      stoneExecutable: stoneAirRun.stoneExecutable,
      stoneTargetFunction: stoneAirRun.stoneTargetFunction,
      stoneExportFunction: stoneAirRun.stoneExportFunction,
      stoneRunnerMainName: stoneAirRun.stoneRunnerMainName,
    },
    fields,
    files: {
      programFile: fileInfo(programFile),
      inputFile: {
        ...fileInfo(inputFile),
        feltCount: inputShape.feltCount,
        arrayWrapped: inputShape.arrayWrapped,
      },
      stoneAirRun: fileInfo(metadataFile),
    },
    warnings,
    notes: [
      'Submit this bundle to Atlantic as multipart/form-data using programFile and inputFile.',
      'Do not submit local stone-proof.json or Integrity split calldata to Atlantic for this path.',
    ],
  };

  const manifestPath = join(absoluteOutDir, 'atlantic-query-bundle.json');
  const submitScriptPath = join(absoluteOutDir, 'submit-atlantic-query.sh');
  manifest.files.manifest = { path: manifestPath };
  manifest.files.submitScript = { path: submitScriptPath };

  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(submitScriptPath, buildCurlScript(manifest));
  chmodSync(submitScriptPath, 0o755);

  return {
    outDir: absoluteOutDir,
    manifest,
    files: {
      manifest: manifestPath,
      submitScript: submitScriptPath,
      programFile,
      inputFile,
      stoneAirRun: metadataFile,
    },
  };
}

