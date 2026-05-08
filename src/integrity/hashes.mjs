import { readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { bigintToHex, parseBigInt } from '../compat/encoding.mjs';

let starknetHash;

function repoRoot() {
  return join(fileURLToPath(new URL('.', import.meta.url)), '../../..');
}

function loadStarknetHash() {
  if (starknetHash) {
    return starknetHash;
  }

  const pnpmDir = join(repoRoot(), 'node_modules', '.pnpm');
  if (!existsSync(pnpmDir)) {
    throw new Error('node_modules/.pnpm not found; cannot load starknet.js hashing helpers');
  }

  const candidate = readdirSync(pnpmDir)
    .filter((name) => name.startsWith('starknet@'))
    .sort()
    .at(-1);

  if (!candidate) {
    throw new Error('starknet.js is not installed in node_modules/.pnpm');
  }

  const packageJson = join(pnpmDir, candidate, 'node_modules', 'starknet', 'package.json');
  const requireFromStarknet = createRequire(packageJson);
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
  const hash = loadStarknetHash();
  return BigInt(hash.computePoseidonHash(bigintToHex(left), bigintToHex(right)));
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

export function calculateVerificationHash(factHash, verifierConfigHash, securityBits) {
  return poseidonManyFelts([
    parseBigInt(factHash, 'factHash'),
    parseBigInt(verifierConfigHash, 'verifierConfigHash'),
    parseBigInt(securityBits, 'securityBits'),
  ]);
}

