import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { bigintToHex, parseBigInt } from '../compat/encoding.mjs';
import {
  calculateBootloadedFactHash,
  calculatePlainFactHash,
  calculateVerificationHash,
  isIntegrityHashingAvailable,
} from './hashes.mjs';

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`failed to read ${label} JSON at ${path}: ${error.message}`);
  }
}

function resolveFromProofRun(proofRunPath, maybePath) {
  if (!maybePath) {
    return undefined;
  }
  return resolve(dirname(proofRunPath), maybePath);
}

function fileMetadata(path) {
  if (!path) {
    return { path: undefined, exists: false };
  }
  if (!existsSync(path)) {
    return { path, exists: false };
  }
  const stat = statSync(path);
  return {
    path,
    exists: true,
    sizeBytes: stat.size,
  };
}

function safeTopLevelKeys(path) {
  if (!path || !existsSync(path)) {
    return { parseable: false, keys: [] };
  }
  try {
    const parsed = readJson(path, 'proof');
    return {
      parseable: true,
      keys: Object.keys(parsed).sort(),
    };
  } catch {
    return { parseable: false, keys: [] };
  }
}

function loadPreparedPublicOutput(preparedJson) {
  const prepared = readJson(preparedJson, 'prepared');
  const rawFelts = prepared.publicOutput?.felts ?? prepared.publicOutput;
  if (!Array.isArray(rawFelts)) {
    throw new Error(`prepared JSON at ${preparedJson} does not contain publicOutput.felts`);
  }
  return {
    labels: prepared.publicOutput?.labels ?? [],
    felts: rawFelts.map((value) => parseBigInt(value, 'publicOutput.felt')),
  };
}

function maybeIntegrityHashes({ publicOutputFelts, programHash, bootloaderProgramHash, verifierConfigHash, securityBits }) {
  const hashingAvailable = isIntegrityHashingAvailable();
  const result = {
    hashingAvailable,
    programHashProvided: programHash !== undefined,
  };

  if (!hashingAvailable || programHash === undefined) {
    return result;
  }

  const plain = calculatePlainFactHash(programHash, publicOutputFelts);
  result.plain = {
    programHash: bigintToHex(parseBigInt(programHash, 'programHash')),
    outputHash: bigintToHex(plain.outputHash),
    factHash: bigintToHex(plain.factHash),
  };

  if (verifierConfigHash !== undefined && securityBits !== undefined) {
    result.plain.verificationHash = bigintToHex(
      calculateVerificationHash(plain.factHash, verifierConfigHash, securityBits),
    );
  }

  if (bootloaderProgramHash !== undefined) {
    const bootloaded = calculateBootloadedFactHash(
      bootloaderProgramHash,
      programHash,
      publicOutputFelts,
    );
    result.bootloaded = {
      bootloaderProgramHash: bigintToHex(parseBigInt(bootloaderProgramHash, 'bootloaderProgramHash')),
      childProgramHash: bigintToHex(parseBigInt(programHash, 'programHash')),
      bootloaderOutputFelts: bootloaded.bootloaderOutput.length,
      bootloaderOutputHash: bigintToHex(bootloaded.bootloaderOutputHash),
      factHash: bigintToHex(bootloaded.factHash),
    };

    if (verifierConfigHash !== undefined && securityBits !== undefined) {
      result.bootloaded.verificationHash = bigintToHex(
        calculateVerificationHash(bootloaded.factHash, verifierConfigHash, securityBits),
      );
    }
  }

  return result;
}

function normalizeProducer(value) {
  const producer = value ?? 'scarb-stwo-local';
  if (!['scarb-stwo-local', 'stone', 'unknown'].includes(producer)) {
    throw new Error(`unsupported proof producer: ${producer}`);
  }
  return producer;
}

export function analyzeProofRunIntegrityCompatibility(proofRunPath, options = {}) {
  const absoluteProofRunPath = resolve(proofRunPath);
  const proofRun = readJson(absoluteProofRunPath, 'proof-run');
  const preparedJson = resolveFromProofRun(absoluteProofRunPath, proofRun.preparedJson);
  const proofJson = resolveFromProofRun(absoluteProofRunPath, proofRun.proofJson);
  const integrityCalldata = options.integrityCalldata
    ? resolve(options.integrityCalldata)
    : undefined;
  const proofProducer = normalizeProducer(options.proofProducer ?? proofRun.proofProducer);

  if (!preparedJson) {
    throw new Error(`proof-run JSON at ${absoluteProofRunPath} does not include preparedJson`);
  }

  const publicOutput = loadPreparedPublicOutput(preparedJson);
  const proofFile = fileMetadata(proofJson);
  const proofJsonShape = safeTopLevelKeys(proofJson);
  const calldataFile = fileMetadata(integrityCalldata);
  const hashes = maybeIntegrityHashes({
    publicOutputFelts: publicOutput.felts,
    programHash: options.programHash,
    bootloaderProgramHash: options.bootloaderProgramHash,
    verifierConfigHash: options.verifierConfigHash,
    securityBits: options.securityBits,
  });

  const blockers = [];
  const warnings = [];

  if (!proofFile.exists) {
    blockers.push('proofJson is missing; run scarb prove/Stone prover first');
  }
  if (!proofJsonShape.parseable && proofFile.exists) {
    blockers.push('proofJson exists but is not parseable JSON');
  }
  if (!hashes.hashingAvailable) {
    blockers.push('starknet.js hashing helpers are unavailable, so outputHash/factHash cannot be computed locally');
  }
  if (!hashes.programHashProvided) {
    blockers.push('program hash is required to compute the Integrity fact hash');
  }
  if (proofProducer !== 'stone') {
    blockers.push('proof was not identified as a Stone/Integrity proof artifact');
    warnings.push('current scarb prove output is useful for local verification, but Integrity submission still needs a Stone-compatible proof/calldata path');
  }
  if (!calldataFile.exists) {
    blockers.push('Integrity proof calldata artifact is missing');
  }

  const localWrapperReady = Boolean(
    publicOutput.felts.length > 0 &&
      hashes.hashingAvailable &&
      hashes.programHashProvided &&
      (hashes.plain || hashes.bootloaded),
  );
  const integritySubmissionReady = blockers.length === 0;

  return {
    proofRunPath: absoluteProofRunPath,
    circuit: proofRun.circuit,
    executable: proofRun.executable,
    executionId: proofRun.executionId,
    proofProducer,
    preparedJson,
    proofJson,
    proofFile,
    proofJsonShape,
    integrityCalldata: calldataFile,
    publicOutput: {
      feltCount: publicOutput.felts.length,
      labels: publicOutput.labels,
      hexFelts: publicOutput.felts.map(bigintToHex),
    },
    hashes,
    localWrapperReady,
    integritySubmissionReady,
    blockers,
    warnings,
    nextSteps: integritySubmissionReady
      ? [
          'submit the Integrity calldata to the selected verifier/FactRegistry flow',
          'use the returned or derived fact hash in the Starknet wrapper call',
        ]
      : [
          'pin the tally Cairo program hash',
          'generate or export a Stone/Integrity-compatible proof artifact',
          'serialize proof calldata accepted by Integrity',
          'rerun this check with --proof-producer stone and --integrity-calldata <path>',
        ],
  };
}
