import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename, dirname, join, relative, resolve } from 'node:path';

const INVENTORY_SCHEMA = 'zkstark-amaci.proof-artifact-inventory.v1';

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

function walk(root) {
  if (!existsSync(root)) {
    return [];
  }
  const out = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(path);
      } else {
        out.push(path);
      }
    }
  }
  return out.sort();
}

function sha256Bytes(bytes) {
  return `0x${createHash('sha256').update(bytes).digest('hex')}`;
}

function sha256File(path) {
  return sha256Bytes(readFileSync(path));
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

function sha256Json(value) {
  return sha256Bytes(Buffer.from(JSON.stringify(canonicalize(value)), 'utf8'));
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

function resolveFromJson(baseJsonPath, maybePath) {
  if (!maybePath) {
    return undefined;
  }
  return resolve(dirname(baseJsonPath), maybePath);
}

function inspectVerifyLog(path) {
  const record = fileRecord(path);
  if (!record.exists) {
    return {
      ...record,
      verified: false,
    };
  }
  return {
    ...record,
    verified: /Verified proof successfully/.test(readFileSync(path, 'utf8')),
  };
}

function inspectPrepared(path) {
  const record = fileRecord(path);
  if (!record.exists) {
    return {
      ...record,
      parseable: false,
      publicOutputFelts: undefined,
      publicOutputLabels: [],
    };
  }
  const prepared = readJson(path, 'prepared');
  const publicOutput = prepared.publicOutput;
  const felts = Array.isArray(publicOutput?.felts)
    ? publicOutput.felts
    : Array.isArray(publicOutput)
      ? publicOutput
      : [];
  return {
    ...record,
    parseable: true,
    publicOutputFelts: felts.length,
    publicOutputLabels: Array.isArray(publicOutput?.labels) ? publicOutput.labels : [],
  };
}

function summarizeEntrypoints(entrypoints) {
  if (!entrypoints || typeof entrypoints !== 'object') {
    return {};
  }
  return Object.fromEntries(
    Object.entries(entrypoints).map(([key, value]) => [
      key,
      Array.isArray(value) ? value.length : undefined,
    ]),
  );
}

function inspectExecutable(path) {
  const record = fileRecord(path);
  if (!record.exists) {
    return {
      ...record,
      parseable: false,
      programBytecodeLength: undefined,
      entrypoints: {},
      localProgramDigest: undefined,
    };
  }
  const executable = readJson(path, 'executable');
  return {
    ...record,
    parseable: true,
    programBytecodeLength: Array.isArray(executable.program?.bytecode)
      ? executable.program.bytecode.length
      : undefined,
    entrypoints: summarizeEntrypoints(executable.entrypoints),
    localProgramDigest: executable.program ? sha256Json(executable.program) : undefined,
  };
}

function inspectProofRun(proofRunPath, targetDevDir, rootDir) {
  const proofRun = readJson(proofRunPath, 'proof-run');
  const proofJson = resolveFromJson(proofRunPath, proofRun.proofJson);
  const preparedJson = resolveFromJson(proofRunPath, proofRun.preparedJson);
  const proveLog = resolveFromJson(proofRunPath, proofRun.proveLog);
  const verifyLog = resolveFromJson(proofRunPath, proofRun.verifyLog);
  const executableJson = proofRun.executable
    ? resolve(targetDevDir, `${proofRun.executable}.executable.json`)
    : undefined;

  const proof = fileRecord(proofJson);
  const prepared = inspectPrepared(preparedJson);
  const verification = inspectVerifyLog(verifyLog);
  const executable = inspectExecutable(executableJson);
  const blockers = [];

  if (!proof.exists) {
    blockers.push('proof JSON is missing');
  }
  if (!prepared.exists) {
    blockers.push('prepared JSON is missing');
  }
  if (!verification.verified) {
    blockers.push('local verify log is missing or does not contain success marker');
  }
  if (!executable.exists) {
    blockers.push('compiled executable artifact is missing');
  } else if (!executable.parseable) {
    blockers.push('compiled executable artifact is not parseable JSON');
  }

  return {
    proofRun: {
      path: proofRunPath,
      relativePath: relative(rootDir, proofRunPath),
      circuit: proofRun.circuit,
      executable: proofRun.executable,
      executionId: proofRun.executionId,
      proofProducer: proofRun.proofProducer,
    },
    artifacts: {
      proofJson: proof,
      preparedJson: prepared,
      proveLog: fileRecord(proveLog),
      verifyLog: verification,
      executableJson: executable,
    },
    localProofReady: blockers.length === 0,
    blockers,
  };
}

function uniqueExecutables(proofRuns) {
  const byName = new Map();
  for (const run of proofRuns) {
    const name = run.proofRun.executable;
    if (!name || byName.has(name)) {
      continue;
    }
    const executable = run.artifacts.executableJson;
    byName.set(name, {
      executable: name,
      path: executable.path,
      exists: executable.exists,
      sizeBytes: executable.sizeBytes,
      sha256: executable.sha256,
      localProgramDigest: executable.localProgramDigest,
      programBytecodeLength: executable.programBytecodeLength,
      entrypoints: executable.entrypoints,
    });
  }
  return [...byName.values()].sort((a, b) => a.executable.localeCompare(b.executable));
}

function countBy(items, keyFn) {
  const out = {};
  for (const item of items) {
    const key = keyFn(item);
    out[key] = (out[key] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => a.localeCompare(b)));
}

export function createProofArtifactInventory(rootDir, options = {}) {
  const absoluteRootDir = resolve(rootDir);
  const targetDevDir = resolve(options.targetDevDir ?? 'cairo/target/dev');
  const proofRunPaths = walk(absoluteRootDir).filter((path) => basename(path) === 'proof-run.json');
  const proofRuns = proofRunPaths.map((proofRunPath) =>
    inspectProofRun(proofRunPath, targetDevDir, absoluteRootDir),
  );
  const executables = uniqueExecutables(proofRuns);
  const blockerCount = proofRuns.reduce((sum, run) => sum + run.blockers.length, 0);
  const verifiedProofRuns = proofRuns.filter((run) => run.localProofReady).length;

  const inventory = {
    schema: INVENTORY_SCHEMA,
    status: blockerCount === 0 ? 'complete_local_inventory' : 'incomplete_local_inventory',
    rootDir: absoluteRootDir,
    targetDevDir,
    counts: {
      proofRuns: proofRuns.length,
      verifiedProofRuns,
      uniqueExecutables: executables.length,
      blockers: blockerCount,
    },
    byCircuit: countBy(proofRuns, (run) => run.proofRun.circuit ?? 'unknown'),
    byExecutable: countBy(proofRuns, (run) => run.proofRun.executable ?? 'unknown'),
    executables,
    proofRuns,
    warnings: [
      'localProgramDigest is a deterministic content digest of executable.program; it is not a canonical Starknet native proof_facts program hash',
      'Scarb/Stwo proof.json currently does not expose the final native transaction proof/proof_facts serialization used for broadcast',
    ],
  };

  if (options.out) {
    writeJson(resolve(options.out), inventory);
  }
  return inventory;
}
