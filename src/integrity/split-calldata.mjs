import {
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
    full: existsSync(fullPath) ? readFeltFile(fullPath) : undefined,
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

function runSwiftnessSerializer({ calldataGeneratorDir, stoneProofPath, outDir, settings }) {
  const cwd = join(resolve(calldataGeneratorDir), 'cli');
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
    '--out',
    outDir,
  ];
  const result = spawnSync(command[0], command.slice(1), {
    cwd,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 1024,
  });
  return { command, cwd, result };
}

function ensureEmptyDir(dir) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
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

    if (stoneCli) {
      const serialized = runStoneCliSerializer({
        stoneCli,
        stoneProofPath,
        outDir: calldataDir,
        settings: normalizedSettings,
      });
      if (serialized.result.status !== 0) {
        throw new Error(
          [
            `stone-cli serialize-proof failed with status ${serialized.result.status}`,
            serialized.result.stderr,
            serialized.result.stdout,
          ]
            .filter(Boolean)
            .join('\n'),
        );
      }
      serializer = {
        mode: 'stone-cli-split',
        command: serialized.command,
      };
    } else if (calldataGeneratorDir) {
      const serialized = runSwiftnessSerializer({
        calldataGeneratorDir,
        stoneProofPath,
        outDir: calldataDir,
        settings: normalizedSettings,
      });
      if (serialized.result.status !== 0) {
        throw new Error(
          [
            `swiftness split calldata generation failed with status ${serialized.result.status}`,
            serialized.result.stderr,
            serialized.result.stdout,
          ]
            .filter(Boolean)
            .join('\n'),
        );
      }
      serializer = {
        mode: 'swiftness-split',
        command: serialized.command,
        cwd: serialized.cwd,
        stdout: serialized.result.stdout.trim(),
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
