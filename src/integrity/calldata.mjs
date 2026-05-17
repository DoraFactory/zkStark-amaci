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
  const jsonCalldata =
    Array.isArray(parsedJson) || (parsedJson && typeof parsedJson === 'object')
      ? extractCalldata(parsedJson)
      : undefined;
  const rawValues = jsonCalldata ?? parsePlainCalldata(source);
  if (!Array.isArray(rawValues) || rawValues.length === 0) {
    throw new Error('Integrity calldata must be a non-empty felt array or raw felt list');
  }
  return rawValues.map((value, index) => normalizeFelt(value, index));
}
