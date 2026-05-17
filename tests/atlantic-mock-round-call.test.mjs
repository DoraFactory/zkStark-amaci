import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAtlanticFactCandidates,
  buildAtlanticMockRoundCall,
  extractNativeTallyPublicOutput,
  SHARP_BOOTLOADER_PROGRAM_HASH,
} from '../src/atlantic/mock-round-call.mjs';
import { calculateBootloadedFactHash, calculatePlainFactHash } from '../src/integrity/hashes.mjs';
import { bigintToHex } from '../src/compat/encoding.mjs';

const nativeTallyOutput = [
  0x4d414349535441524bn,
  2n,
  0x414d4143495f54414c4c595f4e4154495645n,
  0x535441524b4e45545f504f534549444f4en,
  2n,
  1n,
  1n,
  0xf00000000n,
  0x101n,
  0x202n,
  0x303n,
  0x404n,
];

function metadataWithNativeTallyOutput() {
  return {
    program_hash: '0x9999',
    child_program_hash: '0x1234',
    output: ['0x0', '0x1', ...nativeTallyOutput.map(bigintToHex), '0x2'],
  };
}

test('extracts the embedded native tally public output from Atlantic metadata output', () => {
  assert.deepEqual(
    extractNativeTallyPublicOutput(metadataWithNativeTallyOutput().output),
    nativeTallyOutput,
  );
});

test('builds a mock-round submit command only when an Integrity fact candidate matches', () => {
  const metadata = metadataWithNativeTallyOutput();
  const fact = calculatePlainFactHash(0x1234n, nativeTallyOutput);
  const summary = {
    id: 'query-1',
    status: 'DONE',
    result: 'PROOF_VERIFICATION_ON_L2',
    programHash: '0x1234',
    integrityFactHash: bigintToHex(fact.factHash),
    isFactMocked: false,
    isProofMocked: false,
  };

  const result = buildAtlanticMockRoundCall({
    summary,
    metadata,
    wrapperAddress: '0xabc',
    profile: 'amaci_sepolia',
  });

  assert.equal(result.blockers.length, 0);
  assert.equal(result.selectedCandidate.mode, 'plain');
  assert.equal(result.tallyState.stateCommitment, '0x101');
  assert.equal(result.tallyState.currentTallyCommitment, '0x202');
  assert.equal(result.tallyState.newTallyCommitment, '0x303');
  assert.match(result.submit.command, /submit_tally_plain_output_fact/);
  assert.match(result.submit.command, /--profile amaci_sepolia/);
  assert.doesNotMatch(result.submit.command, /--fee-token/);
  assert.match(result.submit.command, /12 0x4d414349535441524b/);
});

test('reports a blocker when Atlantic fact shape is not reconstructed locally', () => {
  const metadata = metadataWithNativeTallyOutput();
  const summary = {
    id: 'query-1',
    status: 'DONE',
    result: 'PROOF_VERIFICATION_ON_L2',
    programHash: '0x1234',
    integrityFactHash: '0xdead',
    isFactMocked: false,
    isProofMocked: false,
  };

  const candidates = buildAtlanticFactCandidates({ summary, metadata });
  assert.equal(candidates.some((entry) => entry.matchesIntegrityFact), false);

  const result = buildAtlanticMockRoundCall({ summary, metadata });
  assert.match(result.blockers.join('\n'), /did not match supported/);
  assert.equal(result.submit.command, undefined);
});

test('recognizes Atlantic metadata-level bootloaded fact shape', () => {
  const metadata = metadataWithNativeTallyOutput();
  const metadataOutput = metadata.output.map((value) => BigInt(value));
  const fact = calculateBootloadedFactHash(
    SHARP_BOOTLOADER_PROGRAM_HASH,
    metadata.program_hash,
    metadataOutput,
  );
  const summary = {
    id: 'query-1',
    status: 'DONE',
    result: 'PROOF_VERIFICATION_ON_L2',
    programHash: metadata.child_program_hash,
    integrityFactHash: bigintToHex(fact.factHash),
    isFactMocked: false,
    isProofMocked: false,
  };

  const result = buildAtlanticMockRoundCall({
    summary,
    metadata,
    wrapperAddress: '0xabc',
    profile: 'amaci_sepolia',
  });

  assert.equal(result.selectedCandidate.mode, 'bootloaded');
  assert.equal(result.selectedCandidate.outputLabel, 'metadata-output');
  assert.equal(result.selectedCandidate.childProgramHashRole, 'metadata-program');
  assert.equal(result.selectedCandidate.bootloaderLabel, 'sharp');
  assert.equal(result.submit.supportedByCurrentWrapper, true);
  assert.equal(result.submit.function, 'submit_tally_atlantic_metadata_fact');
  assert.match(result.submit.command, /submit_tally_atlantic_metadata_fact/);
  assert.match(result.submit.command, /0x9999/);
  assert.equal(result.blockers.length, 0);
});
