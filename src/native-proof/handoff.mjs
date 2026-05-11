import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { basename, dirname, join, resolve } from 'node:path';
import { bigintToHex, parseBigInt } from '../compat/encoding.mjs';
import { calculatePlainFactHash, isIntegrityHashingAvailable } from '../integrity/hashes.mjs';

const require = createRequire(import.meta.url);
const HANDOFF_SCHEMA = 'zkstark-amaci.native-stwo-handoff.v1';

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

function resolveFromProofRun(proofRunPath, maybePath) {
  if (!maybePath) {
    return undefined;
  }
  return resolve(dirname(proofRunPath), maybePath);
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

function safeReadJson(path) {
  if (!path || !existsSync(path)) {
    return { parseable: false, value: undefined, keys: [] };
  }
  try {
    const parsed = readJson(path, 'proof');
    return {
      parseable: true,
      value: parsed,
      keys: Object.keys(parsed).sort(),
    };
  } catch {
    return { parseable: false, value: undefined, keys: [] };
  }
}

function classifyProofJson(path, proofProducer) {
  const parsed = safeReadJson(path);
  if (!path) {
    return {
      kind: 'missing',
      parseable: false,
      keys: [],
      description: 'proofJson path is not set',
    };
  }
  if (!existsSync(path)) {
    return {
      kind: 'missing',
      parseable: false,
      keys: [],
      description: 'proofJson path does not exist',
    };
  }
  if (!parsed.parseable) {
    return {
      kind: 'unparseable-json',
      parseable: false,
      keys: [],
      description: 'proofJson exists but is not parseable JSON',
    };
  }
  if (proofProducer === 'scarb-stwo-local') {
    return {
      kind: 'scarb-stwo-local-proof',
      parseable: true,
      keys: parsed.keys,
      description: 'Scarb/Stwo proof artifact verified by scarb verify',
    };
  }
  return {
    kind: 'unsupported-proof-producer',
    parseable: true,
    keys: parsed.keys,
    description: 'native Starknet handoff currently expects a Scarb/Stwo local proof artifact',
  };
}

function inspectVerificationLog(path) {
  const metadata = fileRecord(path);
  if (!metadata.exists) {
    return {
      ...metadata,
      verified: false,
      description: 'verify log is missing',
    };
  }
  const source = readFileSync(path, 'utf8');
  const verified = /Verified proof successfully/.test(source);
  return {
    ...metadata,
    verified,
    description: verified
      ? 'local scarb verify succeeded'
      : 'verify log does not contain a successful local verification marker',
  };
}

function loadPreparedPublicOutput(preparedJson) {
  const prepared = readJson(preparedJson, 'prepared');
  const rawFelts = Array.isArray(prepared.publicOutput?.felts)
    ? prepared.publicOutput.felts
    : prepared.publicOutput;

  if (!Array.isArray(rawFelts)) {
    throw new Error(`prepared JSON at ${preparedJson} does not contain publicOutput.felts`);
  }

  const felts = rawFelts.map((value, index) => parseBigInt(value, `publicOutput.felts[${index}]`));
  const labels = Array.isArray(prepared.publicOutput?.labels)
    ? prepared.publicOutput.labels
    : felts.map((_, index) => `public_output_${index}`);

  return {
    labels,
    felts,
    decimalFelts: felts.map((felt) => felt.toString(10)),
    hexFelts: felts.map(bigintToHex),
  };
}

function findPackageRoot(packageName) {
  let entry;
  try {
    entry = require.resolve(packageName);
  } catch {
    return undefined;
  }

  let current = dirname(entry);
  while (current !== dirname(current)) {
    const packageJson = join(current, 'package.json');
    if (existsSync(packageJson)) {
      try {
        const parsed = readJson(packageJson, `${packageName} package`);
        if (parsed.name === packageName) {
          return { root: current, packageJson, version: parsed.version };
        }
      } catch {
        return undefined;
      }
    }
    current = dirname(current);
  }
  return undefined;
}

function detectStarknetJsProofSupport() {
  const pkg = findPackageRoot('starknet');
  if (!pkg) {
    return {
      package: 'starknet',
      installed: false,
      version: undefined,
      supportsProofFactsField: false,
      supportsNativeProofTransaction: false,
      inspectedFiles: [],
    };
  }

  const candidates = [
    join(pkg.root, 'dist', 'index.d.ts'),
    join(pkg.root, 'dist', 'index.js'),
    join(pkg.root, 'dist', 'index.global.js'),
  ];
  const inspectedFiles = [];
  let supportsProofFactsField = false;

  for (const candidate of candidates) {
    if (!existsSync(candidate)) {
      continue;
    }
    inspectedFiles.push(candidate);
    const source = readFileSync(candidate, 'utf8');
    supportsProofFactsField ||= /proof_facts|proofFacts/.test(source);
  }

  return {
    package: 'starknet',
    installed: true,
    version: pkg.version,
    supportsProofFactsField,
    supportsNativeProofTransaction: supportsProofFactsField,
    inspectedFiles,
  };
}

function maybeProgramOutputFact({ publicOutputFelts, programHash }) {
  const hashingAvailable = isIntegrityHashingAvailable();
  const result = {
    hashingAvailable,
    programHashProvided: programHash !== undefined,
  };

  if (!hashingAvailable || programHash === undefined) {
    return result;
  }

  const normalizedProgramHash = parseBigInt(programHash, 'programHash');
  const plain = calculatePlainFactHash(normalizedProgramHash, publicOutputFelts);
  result.programOutputFact = {
    programHash: bigintToHex(normalizedProgramHash),
    publicOutputHash: bigintToHex(plain.outputHash),
    factHash: bigintToHex(plain.factHash),
  };
  return result;
}

function buildCandidateProofFacts(programOutputFact) {
  if (!programOutputFact) {
    return {
      schema: `${HANDOFF_SCHEMA}.proof-facts`,
      mode: 'program-output-binding',
      labels: [],
      felts: [],
      note: 'program hash and Starknet Poseidon hashing are required before candidate proof_facts can be exported',
    };
  }

  return {
    schema: `${HANDOFF_SCHEMA}.proof-facts`,
    mode: 'program-output-binding',
    labels: ['program_hash', 'public_output_hash', 'program_output_fact_hash'],
    felts: [
      programOutputFact.programHash,
      programOutputFact.publicOutputHash,
      programOutputFact.factHash,
    ],
    note:
      'candidate proof_facts bind the Cairo program hash to the prepared public output; final Starknet transaction serialization must be pinned to the node/client version',
  };
}

function explicitStatus(report) {
  if (report.nativeBroadcastReady) {
    return 'native_broadcast_ready';
  }
  if (report.nativeHandoffReady) {
    return 'native_handoff_ready';
  }
  if (report.localProofReady) {
    return 'local_proof_ready';
  }
  return 'not_ready';
}

function maybeCopy(path, outDir, name) {
  if (!path || !existsSync(path)) {
    return undefined;
  }
  const destination = join(outDir, name ?? basename(path));
  copyFileSync(path, destination);
  return destination;
}

export function analyzeNativeStwoHandoff(proofRunPath, options = {}) {
  const absoluteProofRunPath = resolve(proofRunPath);
  const proofRun = readJson(absoluteProofRunPath, 'proof-run');
  const proofProducer = options.proofProducer ?? proofRun.proofProducer ?? 'scarb-stwo-local';
  const preparedJson = resolveFromProofRun(absoluteProofRunPath, proofRun.preparedJson);
  const proofJson = resolveFromProofRun(absoluteProofRunPath, proofRun.proofJson);
  const proveLog = resolveFromProofRun(absoluteProofRunPath, proofRun.proveLog);
  const verifyLog = resolveFromProofRun(absoluteProofRunPath, proofRun.verifyLog);

  if (!preparedJson) {
    throw new Error(`proof-run JSON at ${absoluteProofRunPath} does not include preparedJson`);
  }

  const publicOutput = loadPreparedPublicOutput(preparedJson);
  const proofFile = fileRecord(proofJson);
  const proofArtifact = classifyProofJson(proofJson, proofProducer);
  const localVerification = inspectVerificationLog(verifyLog);
  const hashes = maybeProgramOutputFact({
    publicOutputFelts: publicOutput.felts,
    programHash: options.programHash,
  });
  const starknetJs = detectStarknetJsProofSupport();

  const blockers = [];
  const warnings = [];

  if (proofProducer !== 'scarb-stwo-local') {
    blockers.push('native Starknet/S-two handoff currently expects proofProducer = scarb-stwo-local');
  }
  if (!proofFile.exists) {
    blockers.push('proofJson is missing; run scarb prove --execute first');
  }
  if (!proofArtifact.parseable && proofFile.exists) {
    blockers.push('proofJson exists but is not parseable JSON');
  }
  if (!localVerification.verified) {
    blockers.push('verify log does not prove that scarb verify succeeded');
  }
  if (publicOutput.felts.length === 0) {
    blockers.push('prepared public output is empty');
  }
  if (!hashes.hashingAvailable) {
    blockers.push('starknet.js hashing helpers are unavailable, so public output binding cannot be computed');
  }
  if (!hashes.programHashProvided) {
    blockers.push('program hash is required to compute native proof_facts binding');
  }
  if (!starknetJs.supportsNativeProofTransaction) {
    warnings.push(
      'installed starknet.js package does not expose proof_facts/proofFacts transaction fields; this package is a handoff artifact, not a broadcaster',
    );
  }
  const proofJsonMappedToTransaction = options.proofJsonMappedToTransaction === true;
  if (!proofJsonMappedToTransaction) {
    warnings.push(
      'Scarb/Stwo proof JSON has not yet been mapped into the native transaction proof field',
    );
  }
  warnings.push(
    'candidate proof_facts schema is project-local until the exact Starknet RPC/client proof field serialization is pinned',
  );

  const localProofReady = Boolean(
    proofProducer === 'scarb-stwo-local' &&
      proofFile.exists &&
      proofArtifact.parseable &&
      localVerification.verified,
  );
  const nativeWrapperReady = Boolean(
    publicOutput.felts.length > 0 &&
      hashes.hashingAvailable &&
      hashes.programHashProvided &&
      hashes.programOutputFact,
  );
  const nativeHandoffReady = localProofReady && nativeWrapperReady;
  const nativeBroadcastReady =
    nativeHandoffReady && starknetJs.supportsNativeProofTransaction && proofJsonMappedToTransaction;
  const candidateProofFacts = buildCandidateProofFacts(hashes.programOutputFact);

  return {
    schema: HANDOFF_SCHEMA,
    proofRunPath: absoluteProofRunPath,
    circuit: proofRun.circuit,
    executable: proofRun.executable,
    executionId: proofRun.executionId,
    proofProducer,
    preparedJson,
    proofJson,
    proveLog,
    verifyLog,
    proofFile,
    proofArtifact,
    localVerification,
    publicOutput: {
      feltCount: publicOutput.felts.length,
      labels: publicOutput.labels,
      felts: publicOutput.decimalFelts,
      hexFelts: publicOutput.hexFelts,
    },
    hashes,
    candidateProofFacts,
    starknetJs,
    proofJsonMappedToTransaction,
    transactionContext: {
      chainId: options.chainId,
      accountAddress: options.accountAddress,
      contractAddress: options.contractAddress,
    },
    localProofReady,
    nativeWrapperReady,
    nativeHandoffReady,
    nativeBroadcastReady,
    blockers,
    warnings,
    nextSteps: nativeBroadcastReady
      ? [
          'broadcast with the pinned Starknet client/native proof transaction schema',
          'submit proof_facts with a Starknet client version that supports native proof transactions',
        ]
      : nativeHandoffReady
        ? [
            'pin a Starknet RPC/client version that exposes native proof/proof_facts transaction fields',
            'map the Scarb/Stwo proof JSON to that client proof field format',
            'treat Stone/Integrity tooling as the fallback path until native broadcast support is wired',
          ]
        : [
            'run scarb prove --execute and scarb verify for the target executable',
            'pin the Cairo program hash for the target executable',
            'rerun export:native-stwo-handoff with --program-hash <felt>',
          ],
  };
}

export function createNativeStwoHandoffPackage(proofRunPath, outDir, options = {}) {
  const absoluteOutDir = resolve(outDir);
  mkdirSync(absoluteOutDir, { recursive: true });

  const readiness = analyzeNativeStwoHandoff(proofRunPath, options);
  const proofRun = readJson(readiness.proofRunPath, 'proof-run');

  const copied = {
    proofRunJson: maybeCopy(readiness.proofRunPath, absoluteOutDir, 'proof-run.json'),
    preparedJson: maybeCopy(readiness.preparedJson, absoluteOutDir, 'prepared.json'),
    proofJson: maybeCopy(readiness.proofJson, absoluteOutDir, 'proof.json'),
    proveLog: maybeCopy(readiness.proveLog, absoluteOutDir, 'prove.log'),
    verifyLog: maybeCopy(readiness.verifyLog, absoluteOutDir, 'verify.log'),
  };

  const manifest = {
    schema: HANDOFF_SCHEMA,
    status: explicitStatus(readiness),
    circuit: readiness.circuit,
    executable: readiness.executable,
    executionId: readiness.executionId,
    proofProducer: readiness.proofProducer,
    proofArtifactKind: readiness.proofArtifact.kind,
    localProofReady: readiness.localProofReady,
    nativeWrapperReady: readiness.nativeWrapperReady,
    nativeHandoffReady: readiness.nativeHandoffReady,
    nativeBroadcastReady: readiness.nativeBroadcastReady,
    proofJsonMappedToTransaction: readiness.proofJsonMappedToTransaction,
    blockers: readiness.blockers,
    warnings: readiness.warnings,
    nextSteps: readiness.nextSteps,
    starknetJs: readiness.starknetJs,
    transactionContext: readiness.transactionContext,
    source: {
      proofRun: fileRecord(readiness.proofRunPath),
      preparedJson: fileRecord(readiness.preparedJson),
      proofJson: fileRecord(readiness.proofJson),
      proveLog: fileRecord(readiness.proveLog),
      verifyLog: fileRecord(readiness.verifyLog),
    },
    copied,
  };

  const proofFacts = {
    schema: `${HANDOFF_SCHEMA}.proof-facts`,
    status: readiness.nativeHandoffReady ? 'candidate_ready' : 'not_ready',
    proofProducer: readiness.proofProducer,
    candidateProofFacts: readiness.candidateProofFacts,
    publicOutput: readiness.publicOutput,
    hashes: readiness.hashes,
    starknetJs: readiness.starknetJs,
    proofJsonMappedToTransaction: readiness.proofJsonMappedToTransaction,
    transactionContext: readiness.transactionContext,
  };

  const files = {
    manifest: join(absoluteOutDir, 'native-handoff-manifest.json'),
    readiness: join(absoluteOutDir, 'native-readiness.json'),
    proofFacts: join(absoluteOutDir, 'native-proof-facts.json'),
    publicOutput: join(absoluteOutDir, 'public-output.json'),
  };

  writeJson(files.manifest, manifest);
  writeJson(files.readiness, readiness);
  writeJson(files.proofFacts, proofFacts);
  writeJson(files.publicOutput, readiness.publicOutput);

  return {
    outDir: absoluteOutDir,
    files,
    manifest,
    readiness,
    proofFacts,
    proofRun,
  };
}
