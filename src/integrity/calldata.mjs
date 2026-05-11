import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const FELT_RE = /^(0x[0-9a-fA-F]+|[0-9]+)$/;

function readJsonMaybe(source) {
  try {
    return JSON.parse(source);
  } catch {
    return undefined;
  }
}

function extractCalldata(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (!value || typeof value !== 'object') {
    return undefined;
  }
  for (const key of ['calldata', 'proofCalldata', 'proof_calldata', 'integrityCalldata']) {
    if (Array.isArray(value[key])) {
      return value[key];
    }
  }
  return undefined;
}

function parsePlainCalldata(source) {
  const stripped = source
    .split('\n')
    .map((line) => line.replace(/#.*/, '').trim())
    .filter(Boolean)
    .join(' ');
  return stripped
    .split(/[\s,]+/)
    .map((token) => token.trim())
    .filter(Boolean);
}

function normalizeFelt(value, index) {
  if (typeof value === 'bigint') {
    if (value < 0n) {
      throw new Error(`calldata[${index}] must be non-negative`);
    }
    return value.toString();
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`calldata[${index}] must be a non-negative safe integer`);
    }
    return value.toString();
  }
  if (typeof value !== 'string' || !FELT_RE.test(value)) {
    throw new Error(`calldata[${index}] must be a decimal or hex felt`);
  }
  return value;
}

export function parseIntegrityCalldata(source) {
  const parsedJson = readJsonMaybe(source);
  const rawValues = parsedJson === undefined ? parsePlainCalldata(source) : extractCalldata(parsedJson);
  if (!Array.isArray(rawValues) || rawValues.length === 0) {
    throw new Error('Integrity calldata must be a non-empty felt array or raw felt list');
  }
  return rawValues.map((value, index) => normalizeFelt(value, index));
}

function fileMetadata(path) {
  if (!path || !existsSync(path)) {
    return {
      path,
      exists: false,
    };
  }
  const stat = statSync(path);
  const hash = createHash('sha256');
  hash.update(readFileSync(path));
  return {
    path,
    exists: true,
    sizeBytes: stat.size,
    sha256: `0x${hash.digest('hex')}`,
  };
}

function runSerializer({ stoneProofPath, proofSerializer, integrityRepo }) {
  const proof = readFileSync(stoneProofPath);
  if (proofSerializer) {
    const result = spawnSync(resolve(proofSerializer), [], {
      input: proof,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 1024,
    });
    return {
      command: [resolve(proofSerializer)],
      result,
    };
  }

  if (integrityRepo) {
    const result = spawnSync('cargo', ['run', '--release', '--bin', 'proof_serializer'], {
      cwd: resolve(integrityRepo),
      input: proof,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 1024,
    });
    return {
      command: ['cargo', 'run', '--release', '--bin', 'proof_serializer'],
      cwd: resolve(integrityRepo),
      result,
    };
  }

  throw new Error('either proofSerializer or integrityRepo is required');
}

export function buildIntegrityCalldataPackage({
  stoneProofPath,
  rawCalldataPath,
  proofSerializer,
  integrityRepo,
  out,
}) {
  if (!out) {
    throw new Error('out path is required');
  }
  if (!stoneProofPath && !rawCalldataPath) {
    throw new Error('stoneProofPath or rawCalldataPath is required');
  }
  if (stoneProofPath && !existsSync(stoneProofPath)) {
    throw new Error(`Stone proof JSON not found: ${stoneProofPath}`);
  }
  if (rawCalldataPath && !existsSync(rawCalldataPath)) {
    throw new Error(`raw calldata not found: ${rawCalldataPath}`);
  }

  let source;
  let serializer = undefined;
  if (rawCalldataPath) {
    source = readFileSync(rawCalldataPath, 'utf8');
    serializer = {
      mode: 'wrap-raw-calldata',
      rawCalldata: fileMetadata(resolve(rawCalldataPath)),
    };
  } else {
    const serialized = runSerializer({
      stoneProofPath,
      proofSerializer,
      integrityRepo,
    });
    if (serialized.result.status !== 0) {
      throw new Error(
        [
          `proof_serializer failed with status ${serialized.result.status}`,
          serialized.result.stderr,
          serialized.result.stdout,
        ]
          .filter(Boolean)
          .join('\n'),
      );
    }
    source = serialized.result.stdout;
    serializer = {
      mode: 'proof-serializer',
      command: serialized.command,
      cwd: serialized.cwd,
    };
  }

  const calldata = parseIntegrityCalldata(source);
  const output = {
    schema: 'zkstark-amaci.integrity-calldata.v1',
    proofProducer: 'stone',
    serializer,
    source: {
      stoneProof: fileMetadata(stoneProofPath ? resolve(stoneProofPath) : undefined),
    },
    calldata,
    calldataFelts: calldata.length,
  };

  writeFileSync(resolve(out), `${JSON.stringify(output, null, 2)}\n`);
  return {
    out: resolve(out),
    calldataFelts: calldata.length,
    output,
  };
}
