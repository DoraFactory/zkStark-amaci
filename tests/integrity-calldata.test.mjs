import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildIntegrityCalldataPackage,
  parseIntegrityCalldata,
} from '../src/integrity/calldata.mjs';
import { buildIntegritySplitCalldataPackage } from '../src/integrity/split-calldata.mjs';

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

const INTEGRITY_STONE_ANNOTATIONS = [
  'V->P: /cpu air/STARK/Interaction: Interaction element #0: Field Element(0x1)',
  'V->P: /cpu air/STARK/Interaction: Interaction element #1: Field Element(0x2)',
  'V->P: /cpu air/STARK/Interaction: Interaction element #2: Field Element(0x3)',
  'P->V[0:32]: /cpu air/STARK/Original/Commit on Trace: Trace commitment: Hash(0x4)',
  'P->V[32:64]: /cpu air/STARK/Interaction/Commit on Trace: Trace commitment: Hash(0x5)',
  'P->V[64:96]: /cpu air/STARK/Out Of Domain Sampling/Commit on Trace: Trace commitment: Hash(0x6)',
  'P->V[96:128]: /cpu air/STARK/Out Of Domain Sampling/OODS values: Field Elements(0x7,0x8,0x9)',
];

const INTEGRITY_STONE_SINGLE_OODS_ANNOTATIONS = [
  ...INTEGRITY_STONE_ANNOTATIONS.slice(0, -1),
  'P->V[96:128]: /cpu air/STARK/Out Of Domain Sampling/OODS values: 0: Field Element(0x7)',
  'P->V[128:160]: /cpu air/STARK/Out Of Domain Sampling/OODS values: 1: Field Element(0x8)',
  'P->V[160:192]: /cpu air/STARK/Out Of Domain Sampling/OODS values: 2: Field Element(0x9)',
];

function writeStoneProofWithIntegrityAnnotations(path) {
  writeJson(path, {
    proof: [],
    annotations: INTEGRITY_STONE_ANNOTATIONS,
  });
}

function writeStoneProofWithSingleOodsAnnotations(path) {
  writeJson(path, {
    proof: [],
    annotations: INTEGRITY_STONE_SINGLE_OODS_ANNOTATIONS,
  });
}

test('parses raw Integrity calldata felt lists', () => {
  assert.deepEqual(parseIntegrityCalldata('1 0x2\n3,4\n# comment\n5'), [
    '1',
    '0x2',
    '3',
    '4',
    '5',
  ]);
});

test('parses JSON Integrity calldata wrappers', () => {
  assert.deepEqual(parseIntegrityCalldata(JSON.stringify({ calldata: ['0x1', 2, '3'] })), [
    '0x1',
    '2',
    '3',
  ]);
});

test('rejects malformed Integrity calldata values', () => {
  assert.throws(() => parseIntegrityCalldata(JSON.stringify({ calldata: ['0x1', 'bad'] })));
});

test('wraps existing raw calldata into standard JSON package', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-calldata-'));
  const rawCalldata = join(dir, 'calldata');
  const out = join(dir, 'integrity-calldata.json');
  writeFileSync(rawCalldata, '1\n0x2\n3\n');

  const result = buildIntegrityCalldataPackage({
    rawCalldataPath: rawCalldata,
    out,
  });

  assert.equal(result.calldataFelts, 3);
  assert.equal(existsSync(out), true);
  const parsed = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(parsed.schema, 'zkstark-amaci.integrity-calldata.v1');
  assert.equal(parsed.proofProducer, 'stone');
  assert.deepEqual(parsed.calldata, ['1', '0x2', '3']);
});

test('runs a proof_serializer-compatible binary and writes calldata JSON', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-serializer-'));
  const fakeSerializer = join(dir, 'proof_serializer');
  const stoneProof = join(dir, 'stone-proof.json');
  const out = join(dir, 'integrity-calldata.json');
  writeStoneProofWithIntegrityAnnotations(stoneProof);
  writeFileSync(fakeSerializer, '#!/usr/bin/env sh\ncat >/dev/null\nprintf "7 0x8 9\\n"\n');
  chmodSync(fakeSerializer, 0o755);

  const result = buildIntegrityCalldataPackage({
    stoneProofPath: stoneProof,
    proofSerializer: fakeSerializer,
    out,
  });

  assert.equal(result.calldataFelts, 3);
  const parsed = JSON.parse(readFileSync(out, 'utf8'));
  assert.deepEqual(parsed.calldata, ['7', '0x8', '9']);
  assert.equal(parsed.source.stoneProof.exists, true);
});

test('wraps split Integrity calldata into standard JSON package', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-split-calldata-'));
  writeFileSync(join(dir, 'initial'), '1 2 3\n');
  writeFileSync(join(dir, 'step1'), '4 5\n');
  writeFileSync(join(dir, 'final'), '6 7\n');
  const out = join(dir, 'integrity-split-calldata.json');

  const result = buildIntegritySplitCalldataPackage({
    splitCalldataDir: dir,
    out,
  });

  assert.equal(result.calldataFelts, 7);
  assert.equal(result.stepCount, 1);
  const parsed = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(parsed.schema, 'zkstark-amaci.integrity-split-calldata.v1');
  assert.equal(parsed.serializationType, 'split');
  assert.equal(parsed.files.initial.feltCount, 3);
  assert.equal(parsed.files.steps[0].feltCount, 2);
  assert.equal(parsed.files.final.feltCount, 2);
  assert.ok(parsed.settings.verifierConfigHash);
});

test('runs swiftness split generator and copies cli/calldata output', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-swiftness-calldata-'));
  const fakeBin = join(dir, 'bin');
  const generatorDir = join(dir, 'integrity-calldata-generator');
  const generatorCliDir = join(generatorDir, 'cli');
  const argsLog = join(dir, 'cargo-args.txt');
  const fakeCargo = join(fakeBin, 'cargo');
  const stoneProof = join(dir, 'stone-proof.json');
  const outDir = join(dir, 'integrity-split');
  const out = join(dir, 'integrity-split-calldata.json');

  mkdirSync(fakeBin, { recursive: true });
  mkdirSync(generatorCliDir, { recursive: true });
  writeFileSync(join(generatorCliDir, 'Cargo.toml'), '[package]\nname = "fake"\nversion = "0.0.0"\n');
  writeStoneProofWithIntegrityAnnotations(stoneProof);
  writeFileSync(
    fakeCargo,
    [
      '#!/usr/bin/env sh',
      `printf "%s\\n" "$@" > ${JSON.stringify(argsLog)}`,
      'mkdir -p calldata',
      'printf "10\\n" > calldata/initial',
      'printf "11 12\\n" > calldata/step1',
      'printf "13\\n" > calldata/final',
      'printf "14 15 16 17\\n" > calldata/full',
    ].join('\n') + '\n',
  );
  chmodSync(fakeCargo, 0o755);

  const previousPath = process.env.PATH;
  process.env.PATH = `${fakeBin}:${previousPath}`;
  try {
    const result = buildIntegritySplitCalldataPackage({
      stoneProofPath: stoneProof,
      calldataGeneratorDir: generatorDir,
      outDir,
      out,
    });

    assert.equal(result.calldataFelts, 4);
    assert.equal(readFileSync(argsLog, 'utf8').includes('\n--out\n'), false);
    assert.equal(existsSync(join(outDir, 'split-calldata', 'initial')), true);
    const parsed = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(parsed.serializer.mode, 'swiftness-split');
    assert.equal(parsed.files.full.feltCount, 4);
  } finally {
    process.env.PATH = previousPath;
  }
});

test('runs swiftness split generator from root Cargo.toml when cli Cargo.toml is absent', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-swiftness-root-calldata-'));
  const fakeBin = join(dir, 'bin');
  const generatorDir = join(dir, 'integrity-calldata-generator');
  const argsLog = join(dir, 'cargo-args.txt');
  const fakeCargo = join(fakeBin, 'cargo');
  const stoneProof = join(dir, 'stone-proof.json');
  const outDir = join(dir, 'integrity-split');
  const out = join(dir, 'integrity-split-calldata.json');

  mkdirSync(fakeBin, { recursive: true });
  mkdirSync(generatorDir, { recursive: true });
  writeFileSync(join(generatorDir, 'Cargo.toml'), '[package]\nname = "fake"\nversion = "0.0.0"\n');
  writeStoneProofWithIntegrityAnnotations(stoneProof);
  writeFileSync(
    fakeCargo,
    [
      '#!/usr/bin/env sh',
      `printf "%s\\n" "$@" > ${JSON.stringify(argsLog)}`,
      'mkdir -p calldata',
      'printf "20\\n" > calldata/initial',
      'printf "21 22\\n" > calldata/step1',
      'printf "23\\n" > calldata/final',
    ].join('\n') + '\n',
  );
  chmodSync(fakeCargo, 0o755);

  const previousPath = process.env.PATH;
  process.env.PATH = `${fakeBin}:${previousPath}`;
  try {
    const result = buildIntegritySplitCalldataPackage({
      stoneProofPath: stoneProof,
      calldataGeneratorDir: generatorDir,
      outDir,
      out,
    });

    assert.equal(result.calldataFelts, 4);
    assert.equal(existsSync(join(outDir, 'split-calldata', 'initial')), true);
    const parsed = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(parsed.serializer.cwd, generatorDir);
  } finally {
    process.env.PATH = previousPath;
  }
});

test('normalizes Stone verifier singleton OODS annotations for swiftness', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-swiftness-oods-normalize-'));
  const fakeBin = join(dir, 'bin');
  const generatorDir = join(dir, 'integrity-calldata-generator');
  const generatorCliDir = join(generatorDir, 'cli');
  const argsLog = join(dir, 'cargo-args.txt');
  const fakeCargo = join(fakeBin, 'cargo');
  const stoneProof = join(dir, 'stone-proof.json');
  const outDir = join(dir, 'integrity-split');
  const out = join(dir, 'integrity-split-calldata.json');
  const normalizedProof = join(outDir, 'stone-proof.integrity-normalized.json');

  mkdirSync(fakeBin, { recursive: true });
  mkdirSync(generatorCliDir, { recursive: true });
  writeFileSync(join(generatorCliDir, 'Cargo.toml'), '[package]\nname = "fake"\nversion = "0.0.0"\n');
  writeStoneProofWithSingleOodsAnnotations(stoneProof);
  writeFileSync(
    fakeCargo,
    [
      '#!/usr/bin/env sh',
      `printf "%s\\n" "$@" > ${JSON.stringify(argsLog)}`,
      'mkdir -p calldata',
      'printf "30\\n" > calldata/initial',
      'printf "31\\n" > calldata/step1',
      'printf "32\\n" > calldata/final',
    ].join('\n') + '\n',
  );
  chmodSync(fakeCargo, 0o755);

  const previousPath = process.env.PATH;
  process.env.PATH = `${fakeBin}:${previousPath}`;
  try {
    const result = buildIntegritySplitCalldataPackage({
      stoneProofPath: stoneProof,
      calldataGeneratorDir: generatorDir,
      outDir,
      out,
    });

    assert.equal(result.calldataFelts, 3);
    assert.equal(readFileSync(argsLog, 'utf8').includes(normalizedProof), true);
    assert.equal(existsSync(normalizedProof), true);
    const normalized = JSON.parse(readFileSync(normalizedProof, 'utf8'));
    assert.equal(
      normalized.annotations.some((line) => line.includes('Field Elements(0x7,0x8,0x9)')),
      true,
    );
    const parsed = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(parsed.serializer.normalizedOodsValueCount, 3);
    assert.equal(parsed.source.integrityStoneProof.exists, true);
  } finally {
    process.env.PATH = previousPath;
  }
});

test('rejects split calldata generation when Stone proof annotations are missing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-missing-annotations-'));
  const generatorDir = join(dir, 'integrity-calldata-generator');
  const stoneProof = join(dir, 'stone-proof.json');
  const outDir = join(dir, 'integrity-split');
  const out = join(dir, 'integrity-split-calldata.json');

  mkdirSync(generatorDir, { recursive: true });
  writeFileSync(join(generatorDir, 'Cargo.toml'), '[package]\nname = "fake"\nversion = "0.0.0"\n');
  writeFileSync(stoneProof, '{"proof":[]}\n');

  assert.throws(
    () =>
      buildIntegritySplitCalldataPackage({
        stoneProofPath: stoneProof,
        calldataGeneratorDir: generatorDir,
        outDir,
        out,
      }),
    /missing annotations/,
  );
});

test('rejects split calldata generation when Stone proof annotations are prover-only', () => {
  const dir = mkdtempSync(join(tmpdir(), 'zkstark-amaci-prover-only-annotations-'));
  const generatorDir = join(dir, 'integrity-calldata-generator');
  const stoneProof = join(dir, 'stone-proof.json');
  const outDir = join(dir, 'integrity-split');
  const out = join(dir, 'integrity-split-calldata.json');

  mkdirSync(generatorDir, { recursive: true });
  writeFileSync(join(generatorDir, 'Cargo.toml'), '[package]\nname = "fake"\nversion = "0.0.0"\n');
  writeJson(stoneProof, {
    proof: [],
    annotations: [
      'P->V[0:32]: /cpu air/STARK/Original/Commit on Trace: Trace commitment: Hash(0x4)',
    ],
  });

  assert.throws(
    () =>
      buildIntegritySplitCalldataPackage({
        stoneProofPath: stoneProof,
        calldataGeneratorDir: generatorDir,
        outDir,
        out,
      }),
    /annotations are incomplete/,
  );
});
