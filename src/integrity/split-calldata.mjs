import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { bigintToHex } from '../compat/encoding.mjs';
import { asciiToFelt, calculateVerifierConfigHash } from './hashes.mjs';
import { parseIntegrityCalldata } from './calldata.mjs';

const DEFAULT_SETTINGS = Object.freeze({
  layout: 'recursive_with_poseidon',
  hasher: 'keccak_160_lsb',
  stoneVersion: 'stone6',
  memoryVerification: 'cairo1',
});

const STEP_RE = /^step([1-9][0-9]*)$/;
const OODS_VALUES_PREFIX = '/cpu air/STARK/Out Of Domain Sampling/OODS values';
const OODS_VALUES_SPAN_RE =
  /^P->V\[\d+:\d+\]: \/cpu air\/STARK\/Out Of Domain Sampling\/OODS values: .*Field Elements\(/;
const OODS_VALUES_SINGLE_RE =
  /^P->V\[(\d+):(\d+)\]: \/cpu air\/STARK\/Out Of Domain Sampling\/OODS values: .*Field Element\(([^)]+)\)/;

function sha256File(path) {
  const hash = createHash('sha256');
  hash.update(readFileSync(path));
  return `0x${hash.digest('hex')}`;
}

function fileMetadata(path) {
  if (!path || !existsSync(path)) {
    return {
      path,
      exists: false,
    };
  }
  const stat = statSync(path);
  const base = {
    path,
    exists: true,
    sizeBytes: stat.size,
  };
  return stat.isFile()
    ? {
        ...base,
        sha256: sha256File(path),
      }
    : {
        ...base,
        kind: stat.isDirectory() ? 'directory' : 'other',
      };
}

function readFeltFile(path) {
  const calldata = parseIntegrityCalldata(readFileSync(path, 'utf8'));
  return {
    ...fileMetadata(path),
    calldata,
    feltCount: calldata.length,
  };
}

function readOptionalFeltFile(path) {
  if (!existsSync(path)) {
    return undefined;
  }

  try {
    return readFeltFile(path);
  } catch (error) {
    return {
      ...fileMetadata(path),
      parseError: error.message,
    };
  }
}

function normalizeOodsAnnotationSpan(proof) {
  if (proof.annotations.some((line) => OODS_VALUES_SPAN_RE.test(String(line)))) {
    return {
      proof,
      normalized: false,
      normalizedOodsValueCount: 0,
    };
  }

  const oodsValues = [];
  for (const line of proof.annotations) {
    const match = OODS_VALUES_SINGLE_RE.exec(String(line));
    if (!match) {
      continue;
    }
    oodsValues.push({
      start: Number(match[1]),
      end: Number(match[2]),
      value: match[3].trim(),
    });
  }

  if (oodsValues.length === 0) {
    return {
      proof,
      normalized: false,
      normalizedOodsValueCount: 0,
    };
  }

  const first = oodsValues[0];
  const last = oodsValues.at(-1);
  const annotations = [...proof.annotations];
  annotations.push(
    `P->V[${first.start}:${last.end}]: ${OODS_VALUES_PREFIX}: Field Elements(${oodsValues
      .map(({ value }) => value)
      .join(',')})`,
  );

  return {
    proof: {
      ...proof,
      annotations,
    },
    normalized: true,
    normalizedOodsValueCount: oodsValues.length,
  };
}

function validateStoneProofHasIntegrityAnnotations(proof, path) {
  const requiredPatterns = [
    {
      label: 'interaction elements',
      pattern: /V->P: \/cpu air\/STARK\/Interaction: Interaction element #\d+: Field Element\(/,
      minimum: 3,
    },
    {
      label: 'original trace commitment',
      pattern: /P->V\[\d+:\d+\]: \/cpu air\/STARK\/Original\/Commit on Trace: .*Hash\(/,
      minimum: 1,
    },
    {
      label: 'interaction trace commitment',
      pattern: /P->V\[\d+:\d+\]: \/cpu air\/STARK\/Interaction\/Commit on Trace: .*Hash\(/,
      minimum: 1,
    },
    {
      label: 'composition trace commitment',
      pattern:
        /P->V\[\d+:\d+\]: \/cpu air\/STARK\/Out Of Domain Sampling\/Commit on Trace: .*Hash\(/,
      minimum: 1,
    },
    {
      label: 'OODS values',
      pattern: OODS_VALUES_SPAN_RE,
      minimum: 1,
    },
  ];
  const missing = requiredPatterns
    .map(({ label, pattern, minimum }) => ({
      label,
      count: proof.annotations.filter((line) => pattern.test(String(line))).length,
      minimum,
    }))
    .filter(({ count, minimum }) => count < minimum);
  if (missing.length > 0) {
    throw new Error(
      [
        `Stone proof annotations are incomplete for Integrity split calldata: ${path}`,
        `Missing: ${missing
          .map(({ label, count, minimum }) => `${label} (${count}/${minimum})`)
          .join(', ')}`,
        'This usually means the proof still contains prover-only annotations.',
        'Regenerate the proof with the current npm run stone:prove:tally; it runs cpu_air_verifier with --annotation_file and rewrites stone-proof.json with verifier annotations.',
      ].join('\n'),
    );
  }
}

function prepareStoneProofForIntegrity(path, outDir) {
  const proof = JSON.parse(readFileSync(path, 'utf8'));
  if (!Object.prototype.hasOwnProperty.call(proof, 'annotations')) {
    throw new Error(
      [
        `Stone proof is missing annotations: ${path}`,
        'Integrity split calldata generation requires a Stone proof produced with --generate_annotations.',
        'Regenerate the proof with npm run stone:prove:tally using the current repository; annotations are enabled by default.',
      ].join('\n'),
    );
  }
  if (!Array.isArray(proof.annotations)) {
    throw new Error(`Stone proof annotations must be an array: ${path}`);
  }

  const normalized = normalizeOodsAnnotationSpan(proof);
  if (!normalized.normalized) {
    validateStoneProofHasIntegrityAnnotations(normalized.proof, path);
    return {
      stoneProofPath: resolve(path),
      normalizedProofPath: undefined,
      normalizedOodsValueCount: 0,
    };
  }

  const normalizedProofPath = resolve(outDir, 'stone-proof.integrity-normalized.json');
  writeFileSync(normalizedProofPath, `${JSON.stringify(normalized.proof, null, 2)}\n`);
  validateStoneProofHasIntegrityAnnotations(normalized.proof, normalizedProofPath);
  return {
    stoneProofPath: normalizedProofPath,
    normalizedProofPath,
    normalizedOodsValueCount: normalized.normalizedOodsValueCount,
  };
}

function normalizeSettings(settings = {}) {
  return {
    layout: settings.layout ?? DEFAULT_SETTINGS.layout,
    hasher: settings.hasher ?? DEFAULT_SETTINGS.hasher,
    stoneVersion: settings.stoneVersion ?? DEFAULT_SETTINGS.stoneVersion,
    memoryVerification: settings.memoryVerification ?? DEFAULT_SETTINGS.memoryVerification,
  };
}

export function readSplitCalldataDirectory(dir) {
  const absoluteDir = resolve(dir);
  const initialPath = join(absoluteDir, 'initial');
  const finalPath = join(absoluteDir, 'final');
  if (!existsSync(initialPath)) {
    throw new Error(`missing split calldata initial file: ${initialPath}`);
  }
  if (!existsSync(finalPath)) {
    throw new Error(`missing split calldata final file: ${finalPath}`);
  }

  const steps = readdirSync(absoluteDir)
    .map((name) => {
      const match = STEP_RE.exec(name);
      return match ? { index: Number(match[1]), path: join(absoluteDir, name) } : undefined;
    })
    .filter(Boolean)
    .sort((left, right) => left.index - right.index)
    .map((step) => ({
      index: step.index,
      name: `step${step.index}`,
      ...readFeltFile(step.path),
    }));

  const fullPath = join(absoluteDir, 'full');
  const contractAddressPath = join(absoluteDir, 'contract_address');
  return {
    dir: absoluteDir,
    initial: readFeltFile(initialPath),
    steps,
    final: readFeltFile(finalPath),
    full: readOptionalFeltFile(fullPath),
    contractAddress: existsSync(contractAddressPath)
      ? readFileSync(contractAddressPath, 'utf8').trim()
      : undefined,
  };
}

function runStoneCliSerializer({ stoneCli, stoneProofPath, outDir, settings }) {
  const command = [
    resolve(stoneCli),
    'serialize-proof',
    '--proof',
    resolve(stoneProofPath),
    '--network',
    'starknet',
    '--serialization_type',
    'split',
    '--output_dir',
    outDir,
    '--layout',
    settings.layout,
  ];
  const result = spawnSync(command[0], command.slice(1), {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 1024,
  });
  return { command, result };
}

function resolveSwiftnessCargoDir(calldataGeneratorDir) {
  const root = resolve(calldataGeneratorDir);
  const candidates = [join(root, 'cli'), root];
  for (const candidate of candidates) {
    if (existsSync(join(candidate, 'Cargo.toml'))) {
      return candidate;
    }
  }

  throw new Error(
    [
      'could not locate integrity calldata generator Cargo.toml',
      `checked: ${candidates.map((candidate) => join(candidate, 'Cargo.toml')).join(', ')}`,
      'clone https://github.com/HerodotusDev/integrity-calldata-generator.git or pass the directory that contains its Cargo.toml',
    ].join('\n'),
  );
}

function runSwiftnessSerializer({ calldataGeneratorDir, stoneProofPath, outDir, settings }) {
  const cwd = resolveSwiftnessCargoDir(calldataGeneratorDir);
  const generatorOutDir = join(cwd, 'calldata');
  ensureEmptyDir(generatorOutDir);
  const command = [
    'cargo',
    'run',
    '--release',
    '--bin',
    'swiftness',
    '--',
    '--layout',
    settings.layout,
    '--hasher',
    settings.hasher,
    '--stone-version',
    settings.stoneVersion,
    '--proof',
    resolve(stoneProofPath),
  ];
  const result = spawnSync(command[0], command.slice(1), {
    cwd,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 1024,
  });
  if (result.status === 0) {
    copySplitCalldataDirectory(generatorOutDir, outDir);
  }
  return { command, cwd, generatorOutDir, result };
}

function ensureEmptyDir(dir) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
}

function copySplitCalldataDirectory(fromDir, toDir) {
  ensureEmptyDir(toDir);
  for (const entry of readdirSync(fromDir, { withFileTypes: true })) {
    if (!entry.isFile()) {
      continue;
    }
    copyFileSync(join(fromDir, entry.name), join(toDir, entry.name));
  }
}

function formatSpawnFailure({ label, status, signal, error, cwd, command, stderr, stdout }) {
  return [
    `${label} failed with status ${status ?? 'null'}${signal ? ` signal ${signal}` : ''}`,
    error ? `error: ${error.message}` : undefined,
    cwd ? `cwd: ${cwd}` : undefined,
    command?.length ? `command: ${command.join(' ')}` : undefined,
    stderr,
    stdout,
  ]
    .filter(Boolean)
    .join('\n');
}

export function buildIntegritySplitCalldataPackage({
  stoneProofPath,
  splitCalldataDir,
  out,
  outDir,
  stoneCli,
  calldataGeneratorDir,
  settings,
}) {
  if (!out) {
    throw new Error('out path is required');
  }
  const normalizedSettings = normalizeSettings(settings);
  let serializer;
  let calldataDir = splitCalldataDir ? resolve(splitCalldataDir) : undefined;
  let integrityStoneProof;

  if (!calldataDir) {
    if (!stoneProofPath) {
      throw new Error('stoneProofPath is required when splitCalldataDir is not supplied');
    }
    if (!existsSync(stoneProofPath)) {
      throw new Error(`Stone proof JSON not found: ${stoneProofPath}`);
    }
    if (!outDir) {
      throw new Error('outDir is required when generating split calldata');
    }
    calldataDir = resolve(outDir, 'split-calldata');
    ensureEmptyDir(calldataDir);
    integrityStoneProof = prepareStoneProofForIntegrity(stoneProofPath, outDir);

    if (stoneCli) {
      const serialized = runStoneCliSerializer({
        stoneCli,
        stoneProofPath: integrityStoneProof.stoneProofPath,
        outDir: calldataDir,
        settings: normalizedSettings,
      });
      if (serialized.result.status !== 0) {
        throw new Error(
          formatSpawnFailure({
            label: 'stone-cli serialize-proof',
            status: serialized.result.status,
            signal: serialized.result.signal,
            error: serialized.result.error,
            command: serialized.command,
            stderr: serialized.result.stderr,
            stdout: serialized.result.stdout,
          }),
        );
      }
      serializer = {
        mode: 'stone-cli-split',
        command: serialized.command,
        normalizedOodsValueCount: integrityStoneProof.normalizedOodsValueCount,
      };
    } else if (calldataGeneratorDir) {
      const serialized = runSwiftnessSerializer({
        calldataGeneratorDir,
        stoneProofPath: integrityStoneProof.stoneProofPath,
        outDir: calldataDir,
        settings: normalizedSettings,
      });
      if (serialized.result.status !== 0) {
        throw new Error(
          formatSpawnFailure({
            label: 'swiftness split calldata generation',
            status: serialized.result.status,
            signal: serialized.result.signal,
            error: serialized.result.error,
            cwd: serialized.cwd,
            command: serialized.command,
            stderr: serialized.result.stderr,
            stdout: serialized.result.stdout,
          }),
        );
      }
      serializer = {
        mode: 'swiftness-split',
        command: serialized.command,
        cwd: serialized.cwd,
        generatorOutDir: serialized.generatorOutDir,
        stdout: serialized.result.stdout.trim(),
        normalizedOodsValueCount: integrityStoneProof.normalizedOodsValueCount,
      };
    } else {
      throw new Error('stoneCli or calldataGeneratorDir is required to generate split calldata');
    }
  } else {
    serializer = {
      mode: 'wrap-split-calldata',
      splitCalldataDir: calldataDir,
    };
  }

  const split = readSplitCalldataDirectory(calldataDir);
  const verifierConfigHash = calculateVerifierConfigHash(normalizedSettings);
  const feltCount =
    split.initial.feltCount +
    split.steps.reduce((sum, step) => sum + step.feltCount, 0) +
    split.final.feltCount;

  const output = {
    schema: 'zkstark-amaci.integrity-split-calldata.v1',
    proofProducer: 'stone',
    serializationType: 'split',
    settings: {
      ...normalizedSettings,
      verifierConfigHash: bigintToHex(verifierConfigHash),
      encoded: {
        layout: bigintToHex(asciiToFelt(normalizedSettings.layout, 'layout')),
        hasher: bigintToHex(asciiToFelt(normalizedSettings.hasher, 'hasher')),
        stoneVersion: bigintToHex(asciiToFelt(normalizedSettings.stoneVersion, 'stoneVersion')),
        memoryVerification: bigintToHex(
          asciiToFelt(normalizedSettings.memoryVerification, 'memoryVerification'),
        ),
      },
    },
    source: {
      stoneProof: fileMetadata(stoneProofPath ? resolve(stoneProofPath) : undefined),
      integrityStoneProof: integrityStoneProof?.normalizedProofPath
        ? fileMetadata(integrityStoneProof.normalizedProofPath)
        : undefined,
      splitCalldataDir: fileMetadata(calldataDir),
    },
    serializer,
    files: {
      initial: split.initial,
      steps: split.steps,
      final: split.final,
      full: split.full,
    },
    contractAddress: split.contractAddress,
    calldataFelts: feltCount,
    stepCount: split.steps.length,
  };

  writeFileSync(resolve(out), `${JSON.stringify(output, null, 2)}\n`);
  return {
    out: resolve(out),
    splitCalldataDir: calldataDir,
    calldataFelts: feltCount,
    stepCount: split.steps.length,
    output,
  };
}

export function isSplitCalldataPackage(value) {
  return value?.schema === 'zkstark-amaci.integrity-split-calldata.v1';
}

export function loadSplitCalldataPackage(pathOrDir, settings) {
  const absolute = resolve(pathOrDir);
  if (existsSync(absolute) && statSync(absolute).isDirectory()) {
    const split = readSplitCalldataDirectory(absolute);
    const normalizedSettings = normalizeSettings(settings);
    return {
      schema: 'zkstark-amaci.integrity-split-calldata.v1',
      proofProducer: 'stone',
      serializationType: 'split',
      settings: {
        ...normalizedSettings,
        verifierConfigHash: bigintToHex(calculateVerifierConfigHash(normalizedSettings)),
        encoded: {
          layout: bigintToHex(asciiToFelt(normalizedSettings.layout, 'layout')),
          hasher: bigintToHex(asciiToFelt(normalizedSettings.hasher, 'hasher')),
          stoneVersion: bigintToHex(asciiToFelt(normalizedSettings.stoneVersion, 'stoneVersion')),
          memoryVerification: bigintToHex(
            asciiToFelt(normalizedSettings.memoryVerification, 'memoryVerification'),
          ),
        },
      },
      files: {
        initial: split.initial,
        steps: split.steps,
        final: split.final,
        full: split.full,
      },
      contractAddress: split.contractAddress,
      calldataFelts:
        split.initial.feltCount +
        split.steps.reduce((sum, step) => sum + step.feltCount, 0) +
        split.final.feltCount,
      stepCount: split.steps.length,
    };
  }
  return JSON.parse(readFileSync(absolute, 'utf8'));
}

export function splitPackageBasename(packagePath) {
  return basename(resolve(packagePath));
}
