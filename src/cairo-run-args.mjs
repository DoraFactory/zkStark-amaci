import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const FELT_DECIMAL_RE = /^(0|[1-9][0-9]*)$/;
const FELT_HEX_RE = /^0x[0-9a-fA-F]+$/;

export function normalizeFelt(value, index = 0) {
  if (typeof value === 'bigint') {
    if (value < 0n) {
      throw new Error(`argument ${index} must be non-negative`);
    }
    return value.toString();
  }

  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`argument ${index} must be a non-negative integer`);
    }
    return value.toString();
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (FELT_HEX_RE.test(trimmed) || FELT_DECIMAL_RE.test(trimmed)) {
      return trimmed;
    }
  }

  throw new Error(`argument ${index} is not a felt literal: ${String(value)}`);
}

export function parseScarbArgsJson(source) {
  const parsed = JSON.parse(source);
  if (!Array.isArray(parsed)) {
    throw new Error('Scarb executable args JSON must be an array');
  }
  return parsed.map((value, index) => normalizeFelt(value, index));
}

export function formatCairo1RunArgs(felts, options = {}) {
  const { array = true, trailingNewline = true } = options;
  const body = felts.join(' ');
  const text = array ? `[${body}]` : body;
  return trailingNewline ? `${text}\n` : text;
}

export function convertScarbArgsJsonFile(inputPath, outputPath, options = {}) {
  const source = readFileSync(resolve(inputPath), 'utf8');
  const felts = parseScarbArgsJson(source);
  const text = formatCairo1RunArgs(felts, options);
  writeFileSync(resolve(outputPath), text);
  return {
    inputPath: resolve(inputPath),
    outputPath: resolve(outputPath),
    feltCount: felts.length,
    arrayWrapped: options.array !== false,
  };
}
