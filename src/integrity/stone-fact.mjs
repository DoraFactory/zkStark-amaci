import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { bigintToHex, parseBigInt } from '../compat/encoding.mjs';
import { calculatePlainFactHash, poseidonManyFelts } from './hashes.mjs';

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`failed to read ${label} JSON at ${path}: ${error.message}`);
  }
}

function sha256File(path) {
  const hash = createHash('sha256');
  hash.update(readFileSync(path));
  return `0x${hash.digest('hex')}`;
}

function fileRecord(path) {
  const stat = statSync(path);
  return {
    path,
    sizeBytes: stat.size,
    sha256: sha256File(path),
  };
}

function publicInputFromProof(proof) {
  const publicInput = proof.public_input ?? proof.publicInput;
  if (!publicInput || typeof publicInput !== 'object') {
    throw new Error('Stone proof JSON does not contain public_input');
  }
  return publicInput;
}

function segment(publicInput, name) {
  const segmentInfo = publicInput.memory_segments?.[name] ?? publicInput.memorySegments?.[name];
  if (!segmentInfo) {
    throw new Error(`Stone proof public_input does not contain memory segment ${name}`);
  }
  return {
    beginAddr: Number(segmentInfo.begin_addr ?? segmentInfo.beginAddr),
    stopPtr: Number(segmentInfo.stop_ptr ?? segmentInfo.stopPtr),
  };
}

function mainPageValues(publicInput) {
  const publicMemory = publicInput.public_memory ?? publicInput.publicMemory;
  if (!Array.isArray(publicMemory) || publicMemory.length === 0) {
    throw new Error('Stone proof public_input does not contain public_memory');
  }
  return publicMemory
    .filter((cell) => Number(cell.page ?? 0) === 0)
    .sort((left, right) => Number(left.address) - Number(right.address))
    .map((cell) => parseBigInt(cell.value, 'public_memory.value'));
}

export function inspectStoneCairo1Fact(stoneProofPath) {
  const absolutePath = resolve(stoneProofPath);
  const proof = readJson(absolutePath, 'Stone proof');
  const publicInput = publicInputFromProof(proof);
  const outputSegment = segment(publicInput, 'output');
  const outputLen = outputSegment.stopPtr - outputSegment.beginAddr;
  if (!Number.isInteger(outputLen) || outputLen <= 0) {
    throw new Error(`invalid output segment length: ${outputLen}`);
  }

  const memory = mainPageValues(publicInput);
  if (memory.length <= outputLen) {
    throw new Error(
      `public memory has ${memory.length} cells, which is not enough for output length ${outputLen}`,
    );
  }

  const program = memory.slice(0, memory.length - outputLen);
  const output = memory.slice(memory.length - outputLen);
  const programHash = poseidonManyFelts(program);
  const outputHash = poseidonManyFelts(output);
  const fact = calculatePlainFactHash(programHash, output);

  return {
    schema: 'zkstark-amaci.stone-cairo1-fact.v1',
    source: {
      stoneProof: fileRecord(absolutePath),
    },
    publicInput: {
      layout: publicInput.layout,
      nSteps: publicInput.n_steps ?? publicInput.nSteps,
      outputSegment,
      publicMemoryCells: memory.length,
      programCells: program.length,
      outputCells: output.length,
    },
    programHash: bigintToHex(programHash),
    outputHash: bigintToHex(outputHash),
    factHash: bigintToHex(fact.factHash),
    publicOutput: {
      felts: output.map((value) => value.toString()),
      hexFelts: output.map(bigintToHex),
    },
  };
}
