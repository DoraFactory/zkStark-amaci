import { readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { bigintToHex, parseBigInt } from '../compat/encoding.mjs';

let starknetHash;

function repoRoot() {
  return join(fileURLToPath(new URL('.', import.meta.url)), '../..');
}

function loadStarknetHash() {
  if (starknetHash) {
    return starknetHash;
  }

  const roots = [repoRoot(), join(repoRoot(), '..')];
  const packageJsons = [];
  for (const root of roots) {
    const npmPackageJson = join(root, 'node_modules', 'starknet', 'package.json');
    if (existsSync(npmPackageJson)) {
      packageJsons.push(npmPackageJson);
    }

    const pnpmDir = join(root, 'node_modules', '.pnpm');
    if (existsSync(pnpmDir)) {
      const candidate = readdirSync(pnpmDir)
        .filter((name) => name.startsWith('starknet@'))
        .sort()
        .at(-1);
      if (candidate) {
        packageJsons.push(join(pnpmDir, candidate, 'node_modules', 'starknet', 'package.json'));
      }
    }
  }

  if (packageJsons.length === 0) {
    throw new Error('starknet.js is not installed; cannot load hashing helpers');
  }

  const requireFromStarknet = createRequire(packageJsons[0]);
  ({ hash: starknetHash } = requireFromStarknet('starknet'));
  return starknetHash;
}

function normalizeFelts(values) {
  return values.map((value) => bigintToHex(parseBigInt(value)));
}

export function isIntegrityHashingAvailable() {
  try {
    loadStarknetHash();
    return true;
  } catch {
    return false;
  }
}

export function poseidonManyFelts(values) {
  const hash = loadStarknetHash();
  return BigInt(hash.computePoseidonHashOnElements(normalizeFelts(values)));
}

export function poseidonTwoFelts(left, right) {
  return poseidonManyFelts([left, right]);
}

export function calculatePlainFactHash(programHash, outputFelts) {
  const outputHash = poseidonManyFelts(outputFelts);
  const factHash = poseidonTwoFelts(parseBigInt(programHash, 'programHash'), outputHash);
  return {
    outputHash,
    factHash,
  };
}

export function calculateBootloadedFactHash(bootloaderProgramHash, childProgramHash, childOutputFelts) {
  const output = [
    1n,
    BigInt(childOutputFelts.length + 2),
    parseBigInt(childProgramHash, 'childProgramHash'),
    ...childOutputFelts.map((value) => parseBigInt(value)),
  ];
  const bootloaderOutputHash = poseidonManyFelts(output);
  const factHash = poseidonTwoFelts(parseBigInt(bootloaderProgramHash, 'bootloaderProgramHash'), bootloaderOutputHash);
  return {
    bootloaderOutput: output,
    bootloaderOutputHash,
    factHash,
  };
}

export function calculateWrappedBootloadedFactHash(
  wrapperProgramHash,
  bootloaderProgramHash,
  childProgramHash,
  childOutputFelts,
) {
  const bootloaderOutput = [
    1n,
    BigInt(childOutputFelts.length + 2),
    parseBigInt(childProgramHash, 'childProgramHash'),
    ...childOutputFelts.map((value) => parseBigInt(value)),
  ];
  const bootloaderOutputHash = poseidonManyFelts(bootloaderOutput);
  const wrapperOutput = [
    1n,
    4n,
    parseBigInt(wrapperProgramHash, 'wrapperProgramHash'),
    parseBigInt(bootloaderProgramHash, 'bootloaderProgramHash'),
    bootloaderOutputHash,
  ];
  const wrapperOutputHash = poseidonManyFelts(wrapperOutput);
  const factHash = poseidonTwoFelts(parseBigInt(bootloaderProgramHash, 'bootloaderProgramHash'), wrapperOutputHash);
  return {
    bootloaderOutput,
    bootloaderOutputHash,
    wrapperOutput,
    wrapperOutputHash,
    factHash,
  };
}

export function calculateVerificationHash(factHash, verifierConfigHash, securityBits) {
  return poseidonManyFelts([
    parseBigInt(factHash, 'factHash'),
    parseBigInt(verifierConfigHash, 'verifierConfigHash'),
    parseBigInt(securityBits, 'securityBits'),
  ]);
}

export function asciiToFelt(value, label = 'ascii') {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty ASCII string`);
  }
  if (![...value].every((char) => char.charCodeAt(0) <= 0x7f)) {
    throw new Error(`${label} must contain ASCII characters only`);
  }
  return BigInt(`0x${Buffer.from(value, 'ascii').toString('hex')}`);
}

export function calculateVerifierConfigHash({
  layout,
  hasher,
  stoneVersion,
  memoryVerification,
}) {
  return poseidonManyFelts([
    asciiToFelt(layout, 'layout'),
    asciiToFelt(hasher, 'hasher'),
    asciiToFelt(stoneVersion, 'stoneVersion'),
    asciiToFelt(memoryVerification, 'memoryVerification'),
  ]);
}
