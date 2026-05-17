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

function metadataWithOutput(nativeOutput) {
  return {
    program_hash: '0x9999',
    child_program_hash: '0x1234',
    output: ['0x0', '0x1', ...nativeOutput.map(bigintToHex), '0x2'],
  };
}

function metadataBootloadedSummary(metadata) {
  const metadataOutput = metadata.output.map((value) => BigInt(value));
  const fact = calculateBootloadedFactHash(
    SHARP_BOOTLOADER_PROGRAM_HASH,
    metadata.program_hash,
    metadataOutput,
  );
  return {
    id: 'query-1',
    status: 'DONE',
    result: 'PROOF_VERIFICATION_ON_L2',
    programHash: metadata.child_program_hash,
    integrityFactHash: bigintToHex(fact.factHash),
    isFactMocked: false,
    isProofMocked: false,
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
  const summary = metadataBootloadedSummary(metadata);

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

test('builds an Atlantic metadata add-new-key submit command', () => {
  const nativeAddNewKeyOutput = [
    0x4d414349535441524bn,
    2n,
    0x414d4143495f4144445f4b45595f4e4154495645n,
    0x535441524b4e45545f504f534549444f4en,
    2n,
    4n,
    0x10n,
    0x11n,
    0xabcn,
    0x12n,
    0x13n,
    0x14n,
    0x15n,
    0x16n,
    0x17n,
    0x18n,
    0x19n,
    0x1an,
    0x1bn,
  ];
  const metadata = metadataWithOutput(nativeAddNewKeyOutput);
  const result = buildAtlanticMockRoundCall({
    summary: metadataBootloadedSummary(metadata),
    metadata,
    wrapperAddress: '0xabc',
    operation: 'add-new-key',
    state: { newStateCommitment: '0x777' },
  });

  assert.equal(result.blockers.length, 0);
  assert.equal(result.operationState.keyNullifier, '0xabc');
  assert.match(result.submit.command, /submit_add_new_key_atlantic_metadata_fact/);
  assert.match(result.submit.command, /0x777/);
});

test('builds an Atlantic metadata process-messages submit command', () => {
  const nativeProcessMessagesOutput = [
    0x4d414349535441524bn,
    2n,
    0x414d4143495f50524f434553535f4d53475f4e4154495645n,
    0x535441524b4e45545f504f534549444f4en,
    2n,
    1n,
    5n,
    0x20n,
    0x21n,
    0x22n,
    0x23n,
    0x101n,
    0x202n,
    0x303n,
    0x24n,
    0x25n,
  ];
  const metadata = metadataWithOutput(nativeProcessMessagesOutput);
  const result = buildAtlanticMockRoundCall({
    summary: metadataBootloadedSummary(metadata),
    metadata,
    wrapperAddress: '0xabc',
    operation: 'process-messages',
  });

  assert.equal(result.blockers.length, 0);
  assert.equal(result.operationState.currentStateCommitment, '0x101');
  assert.equal(result.operationState.newStateCommitment, '0x202');
  assert.equal(result.operationState.currentDeactivateCommitment, '0x303');
  assert.match(result.submit.command, /submit_process_messages_atlantic_metadata_fact/);
});

test('builds an Atlantic metadata process-deactivate submit command with state override', () => {
  const nativeProcessDeactivateOutput = [
    0x4d414349535441524bn,
    2n,
    0x414d4143495f50524f434553535f44454143545f4e4154495645n,
    0x535441524b4e45545f504f534549444f4en,
    2n,
    4n,
    5n,
    0x30n,
    0x31n,
    0x32n,
    0x33n,
    0x404n,
    0x505n,
    0x606n,
    0x34n,
    0x35n,
  ];
  const metadata = metadataWithOutput(nativeProcessDeactivateOutput);
  const result = buildAtlanticMockRoundCall({
    summary: metadataBootloadedSummary(metadata),
    metadata,
    wrapperAddress: '0xabc',
    operation: 'process-deactivate',
    state: { currentStateCommitment: '0x707' },
  });

  assert.equal(result.blockers.length, 0);
  assert.equal(result.operationState.currentDeactivateCommitment, '0x404');
  assert.equal(result.operationState.newDeactivateCommitment, '0x505');
  assert.equal(result.operationState.currentStateCommitment, '0x707');
  assert.match(result.submit.command, /submit_process_deactivate_atlantic_metadata_fact/);
});
