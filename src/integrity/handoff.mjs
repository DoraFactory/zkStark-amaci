import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { analyzeProofRunIntegrityCompatibility } from './proof-compatibility.mjs';

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`failed to read ${label} JSON at ${path}: ${error.message}`);
  }
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(serializeJson(value), null, 2)}\n`);
}

function serializeJson(value) {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map(serializeJson);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, item]) => item !== undefined)
        .map(([key, item]) => [key, serializeJson(item)]),
    );
  }
  return value;
}

function sha256File(path) {
  const hash = createHash('sha256');
  hash.update(readFileSync(path));
  return `0x${hash.digest('hex')}`;
}

function fileRecord(path) {
  if (!path || !existsSync(path)) {
    return {
      path,
      exists: false,
    };
  }
  const stat = statSync(path);
  return {
    path,
    exists: true,
    sizeBytes: stat.size,
    sha256: sha256File(path),
  };
}

function maybeCopy(path, outDir, name) {
  if (!path || !existsSync(path)) {
    return undefined;
  }
  const destination = join(outDir, name ?? basename(path));
  copyFileSync(path, destination);
  return destination;
}

function explicitStatus(report) {
  if (report.integritySubmissionReady) {
    return 'integrity_submission_ready';
  }
  if (report.localProofReady && report.localWrapperReady) {
    return 'local_proof_and_wrapper_binding_ready';
  }
  if (report.localProofReady) {
    return 'local_proof_ready';
  }
  return 'not_ready';
}

export function createIntegrityHandoffPackage(proofRunPath, outDir, options = {}) {
  const absoluteOutDir = resolve(outDir);
  mkdirSync(absoluteOutDir, { recursive: true });

  const report = analyzeProofRunIntegrityCompatibility(proofRunPath, options);
  const proofRun = readJson(report.proofRunPath, 'proof-run');
  const prepared = readJson(report.preparedJson, 'prepared');

  const copied = {
    proofRunJson: maybeCopy(report.proofRunPath, absoluteOutDir, 'proof-run.json'),
    preparedJson: maybeCopy(report.preparedJson, absoluteOutDir, 'prepared.json'),
    proofJson: maybeCopy(report.proofJson, absoluteOutDir, 'proof.json'),
    verifyLog: maybeCopy(report.verifyLog, absoluteOutDir, 'verify.log'),
    integrityCalldata: maybeCopy(report.integrityCalldata.path, absoluteOutDir, 'integrity-calldata.json'),
  };

  const publicOutput = {
    labels: prepared.publicOutput?.labels ?? report.publicOutput.labels,
    felts: prepared.publicOutput?.felts ?? [],
    hexFelts: prepared.publicOutput?.hexFelts ?? report.publicOutput.hexFelts,
  };

  const wrapperFact = {
    programHash: options.programHash ?? undefined,
    bootloaderProgramHash: options.bootloaderProgramHash ?? undefined,
    verifierConfigHash: options.verifierConfigHash ?? undefined,
    securityBits: options.securityBits ?? undefined,
    hashes: report.hashes,
    note:
      options.programHash === '0x1234' || options.programHash === 0x1234n
        ? '0x1234 is a mock program hash for local binding checks only'
        : undefined,
  };

  const manifest = {
    schema: 'zkstark-amaci.integrity-handoff.v1',
    status: explicitStatus(report),
    circuit: report.circuit,
    executable: report.executable,
    executionId: report.executionId,
    proofProducer: report.proofProducer,
    proofArtifactKind: report.proofArtifact.kind,
    localProofReady: report.localProofReady,
    localWrapperReady: report.localWrapperReady,
    integritySubmissionReady: report.integritySubmissionReady,
    blockers: report.blockers,
    warnings: report.warnings,
    nextSteps: report.nextSteps,
    source: {
      proofRun: fileRecord(report.proofRunPath),
      preparedJson: fileRecord(report.preparedJson),
      proofJson: fileRecord(report.proofJson),
      verifyLog: fileRecord(report.verifyLog),
      integrityCalldata: fileRecord(report.integrityCalldata.path),
    },
    copied,
  };

  const files = {
    manifest: join(absoluteOutDir, 'handoff-manifest.json'),
    readiness: join(absoluteOutDir, 'integrity-readiness.json'),
    publicOutput: join(absoluteOutDir, 'public-output.json'),
    wrapperFact: join(absoluteOutDir, 'wrapper-fact.json'),
  };

  writeJson(files.manifest, manifest);
  writeJson(files.readiness, report);
  writeJson(files.publicOutput, publicOutput);
  writeJson(files.wrapperFact, wrapperFact);

  return {
    outDir: absoluteOutDir,
    files,
    manifest,
    readiness: report,
    proofRun,
  };
}
