import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { bigintToHex, parseBigInt } from '../compat/encoding.mjs';
import {
  calculateBootloadedFactHash,
  calculatePlainFactHash,
  calculateVerificationHash,
  calculateWrappedBootloadedFactHash,
  poseidonManyFelts,
} from '../integrity/hashes.mjs';

export const STONE_BOOTLOADER_PROGRAM_HASH =
  '0x40519557c48b25e7e7d27cb27297300b94909028c327b385990f0b649920cc3';
export const SHARP_BOOTLOADER_PROGRAM_HASH =
  '0x5ab580b04e3532b6b18f81cfa654a05e29dd8e2352d88df1e765a84072db07';
export const CAIRO_VERIFIER_PROGRAM_HASH =
  '0x193641eb151b0f41674641089952e60bc3aded26e3cf42793655c562b8c3aa0';

const FACT_REGISTRY = Object.freeze({
  sepolia: '0x4ce7851f00b6c3289674841fd7a1b96b6fd41ed1edc248faccd672c26371b8c',
  mainnet: '0xcc63a1e8e7824642b89fa6baf996b8ed21fa4707be90ef7605570ca8e4f00b',
});

const SATELLITE = Object.freeze({
  sepolia: '0x00421cd95f9ddabdd090db74c9429f257cb6bc1ccc339278d1db1de39156676e',
  mainnet: '0x01ba7d4b5707f8878c22fb335763abfc26c2ae157c434d597f6416fe6a79bf2e',
});

const PUBLIC_OUTPUT_MAGIC = 0x4d414349535441524bn;
const NATIVE_PUBLIC_OUTPUT_VERSION = 2n;
const TALLY_VOTES_NATIVE_CIRCUIT_ID = 0x414d4143495f54414c4c595f4e4154495645n;
const TALLY_NATIVE_OUTPUT_LEN = 12;

function readJson(path, label) {
  if (!existsSync(path)) {
    throw new Error(`missing ${label}: ${path}`);
  }
  return JSON.parse(readFileSync(path, 'utf8'));
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function normalizeHex(value, label) {
  return bigintToHex(parseBigInt(value, label));
}

function normalizeFeltArray(values, label) {
  if (!Array.isArray(values)) {
    throw new Error(`${label} must be an array`);
  }
  return values.map((value, index) => parseBigInt(value, `${label}[${index}]`));
}

function uniqueCandidates(candidates) {
  const seen = new Set();
  const unique = [];
  for (const entry of candidates.filter(Boolean)) {
    const key = `${entry.label}:${normalizeHex(entry.value, entry.label)}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(entry);
  }
  return unique;
}

function summaryFromInput(value) {
  if (value?.summary) {
    return value.summary;
  }
  if (value?.atlanticQuery) {
    const query = value.atlanticQuery;
    return {
      id: query.id,
      transactionId: query.transactionId,
      status: query.status,
      step: query.step,
      result: query.result,
      network: query.network,
      chain: query.chain,
      layout: query.layout,
      isFactMocked: query.isFactMocked,
      isProofMocked: query.isProofMocked,
      programHash: query.programHash,
      integrityFactHash: query.integrityFactHash,
      sharpFactHash: query.sharpFactHash,
    };
  }
  return value;
}

export function extractNativeTallyPublicOutput(values) {
  const felts = normalizeFeltArray(values, 'metadata.output');
  for (let i = 0; i <= felts.length - TALLY_NATIVE_OUTPUT_LEN; i += 1) {
    if (
      felts[i] === PUBLIC_OUTPUT_MAGIC &&
      felts[i + 1] === NATIVE_PUBLIC_OUTPUT_VERSION &&
      felts[i + 2] === TALLY_VOTES_NATIVE_CIRCUIT_ID
    ) {
      return felts.slice(i, i + TALLY_NATIVE_OUTPUT_LEN);
    }
  }
  return undefined;
}

function candidate(label, mode, fields, factHash, expectedFactHash) {
  const normalizedFactHash = bigintToHex(factHash);
  return {
    label,
    mode,
    ...fields,
    factHash: normalizedFactHash,
    matchesIntegrityFact: expectedFactHash
      ? normalizedFactHash === normalizeHex(expectedFactHash, 'integrityFactHash')
      : false,
  };
}

export function buildAtlanticFactCandidates({ summary, metadata }) {
  const candidates = [];
  const expectedFactHash = summary.integrityFactHash;
  const queryProgramHash = summary.programHash;
  const metadataProgramHash = metadata?.program_hash;
  const metadataChildProgramHash = metadata?.child_program_hash;
  const metadataOutput = metadata?.output ? normalizeFeltArray(metadata.output, 'metadata.output') : undefined;
  const nativeTallyOutput = metadataOutput
    ? extractNativeTallyPublicOutput(metadata.output)
    : undefined;

  const programHashCandidates = uniqueCandidates([
    queryProgramHash ? { label: 'query-program', value: queryProgramHash } : undefined,
    metadataProgramHash ? { label: 'metadata-program', value: metadataProgramHash } : undefined,
    metadataChildProgramHash ? { label: 'metadata-child-program', value: metadataChildProgramHash } : undefined,
  ]);
  const bootloadedChildProgramHashCandidates = uniqueCandidates([
    metadataProgramHash ? { label: 'metadata-program', value: metadataProgramHash } : undefined,
    metadataChildProgramHash ? { label: 'metadata-child-program', value: metadataChildProgramHash } : undefined,
    queryProgramHash ? { label: 'query-program', value: queryProgramHash } : undefined,
  ]);

  const outputSets = [
    nativeTallyOutput
      ? {
          label: 'native-tally-output',
          output: nativeTallyOutput,
        }
      : undefined,
    metadataOutput
      ? {
          label: 'metadata-output',
          output: metadataOutput,
        }
      : undefined,
  ].filter(Boolean);

  for (const { label, output } of outputSets) {
    for (const programHashCandidate of programHashCandidates) {
      const plain = calculatePlainFactHash(programHashCandidate.value, output);
      candidates.push(
        candidate(
          `plain:${label}:${programHashCandidate.label}`,
          'plain',
          {
            outputLabel: label,
            programHashRole: programHashCandidate.label,
            programHash: normalizeHex(programHashCandidate.value, programHashCandidate.label),
            outputHash: bigintToHex(plain.outputHash),
            outputFelts: output.map(bigintToHex),
          },
          plain.factHash,
          expectedFactHash,
        ),
      );
    }

    for (const [bootloaderLabel, bootloaderProgramHash] of [
      ['stone', STONE_BOOTLOADER_PROGRAM_HASH],
      ['sharp', SHARP_BOOTLOADER_PROGRAM_HASH],
    ]) {
      for (const childProgramHashCandidate of bootloadedChildProgramHashCandidates) {
        const bootloaded = calculateBootloadedFactHash(
          bootloaderProgramHash,
          childProgramHashCandidate.value,
          output,
        );
        candidates.push(
          candidate(
            `bootloaded:${label}:${childProgramHashCandidate.label}:${bootloaderLabel}`,
            'bootloaded',
            {
              outputLabel: label,
              bootloaderLabel,
              bootloaderProgramHash,
              childProgramHashRole: childProgramHashCandidate.label,
              childProgramHash: normalizeHex(childProgramHashCandidate.value, childProgramHashCandidate.label),
              outputHash: bigintToHex(bootloaded.bootloaderOutputHash),
              outputFelts: output.map(bigintToHex),
            },
            bootloaded.factHash,
            expectedFactHash,
          ),
        );

        for (const [wrapperLabel, wrapperProgramHash] of [
          ['cairo-verifier', CAIRO_VERIFIER_PROGRAM_HASH],
          metadataProgramHash ? ['metadata-program', metadataProgramHash] : undefined,
        ].filter(Boolean)) {
          const wrapped = calculateWrappedBootloadedFactHash(
            wrapperProgramHash,
            bootloaderProgramHash,
            childProgramHashCandidate.value,
            output,
          );
          candidates.push(
            candidate(
              `wrapped-bootloaded:${label}:${childProgramHashCandidate.label}:${wrapperLabel}:${bootloaderLabel}`,
              'wrapped_bootloaded',
              {
                outputLabel: label,
                wrapperLabel,
                wrapperProgramHash: normalizeHex(wrapperProgramHash, 'wrapperProgramHash'),
                bootloaderLabel,
                bootloaderProgramHash,
                childProgramHashRole: childProgramHashCandidate.label,
                childProgramHash: normalizeHex(childProgramHashCandidate.value, childProgramHashCandidate.label),
                outputHash: bigintToHex(wrapped.wrapperOutputHash),
                outputFelts: output.map(bigintToHex),
              },
              wrapped.factHash,
              expectedFactHash,
            ),
          );
        }
      }
    }
  }

  return candidates;
}

function sncastInvokeCommand({ sncast, profile, contractAddress, functionName, calldata }) {
  return [
    sncast,
    profile ? `--profile ${profile}` : undefined,
    '--wait invoke',
    `--contract-address ${contractAddress}`,
    `--function ${functionName}`,
    `--calldata ${calldata.join(' ')}`,
  ]
    .filter(Boolean)
    .join(' ');
}

function currentWrapperCanSubmitCandidate(candidate, tallyProgramHash) {
  if (!candidate || !tallyProgramHash) {
    return false;
  }
  if (isAtlanticMetadataTallyCandidate(candidate)) {
    return true;
  }
  const expectedProgramHash = normalizeHex(tallyProgramHash, 'tallyProgramHash');
  if (candidate.mode === 'plain') {
    return candidate.programHash === expectedProgramHash;
  }
  if (candidate.mode === 'bootloaded' || candidate.mode === 'wrapped_bootloaded') {
    return candidate.childProgramHash === expectedProgramHash;
  }
  return false;
}

function isAtlanticMetadataTallyCandidate(candidate) {
  return candidate?.mode === 'bootloaded'
    && candidate.outputLabel === 'metadata-output'
    && candidate.childProgramHashRole === 'metadata-program'
    && candidate.bootloaderLabel === 'sharp';
}

function submitTallyCommand({ candidate, wrapperAddress, profile, sncast, state, tallyProgramHash }) {
  if (!candidate || !wrapperAddress) {
    return undefined;
  }
  if (!currentWrapperCanSubmitCandidate(candidate, tallyProgramHash)) {
    return undefined;
  }
  const currentTallyCommitment = normalizeHex(state.currentTallyCommitment, 'currentTallyCommitment');
  const newTallyCommitment = normalizeHex(state.newTallyCommitment, 'newTallyCommitment');
  const stateCommitment = normalizeHex(state.stateCommitment, 'stateCommitment');
  const output = candidate.outputFelts;
  if (isAtlanticMetadataTallyCandidate(candidate)) {
    return sncastInvokeCommand({
      sncast,
      profile,
      contractAddress: wrapperAddress,
      functionName: 'submit_tally_atlantic_metadata_fact',
      calldata: [
        currentTallyCommitment,
        newTallyCommitment,
        stateCommitment,
        candidate.childProgramHash,
        output.length,
        ...output,
        candidate.factHash,
      ],
    });
  }
  if (candidate.mode === 'plain') {
    return sncastInvokeCommand({
      sncast,
      profile,
      contractAddress: wrapperAddress,
      functionName: 'submit_tally_plain_output_fact',
      calldata: [
        currentTallyCommitment,
        newTallyCommitment,
        stateCommitment,
        output.length,
        ...output,
        candidate.factHash,
      ],
    });
  }
  if (candidate.mode === 'bootloaded') {
    return sncastInvokeCommand({
      sncast,
      profile,
      contractAddress: wrapperAddress,
      functionName: 'submit_tally_bootloaded_output_fact',
      calldata: [
        currentTallyCommitment,
        newTallyCommitment,
        stateCommitment,
        candidate.bootloaderProgramHash,
        output.length,
        ...output,
        candidate.factHash,
      ],
    });
  }
  if (candidate.mode === 'wrapped_bootloaded') {
    return sncastInvokeCommand({
      sncast,
      profile,
      contractAddress: wrapperAddress,
      functionName: 'submit_tally_wrapped_bootloaded_output_fact',
      calldata: [
        currentTallyCommitment,
        newTallyCommitment,
        stateCommitment,
        candidate.wrapperProgramHash,
        candidate.bootloaderProgramHash,
        output.length,
        ...output,
        candidate.factHash,
      ],
    });
  }
  return undefined;
}

function tallyStateFromOutput(nativeTallyOutput, overrides = {}) {
  if (!nativeTallyOutput) {
    return undefined;
  }
  return {
    stateCommitment: overrides.stateCommitment ?? bigintToHex(nativeTallyOutput[8]),
    currentTallyCommitment: overrides.currentTallyCommitment ?? bigintToHex(nativeTallyOutput[9]),
    newTallyCommitment: overrides.newTallyCommitment ?? bigintToHex(nativeTallyOutput[10]),
  };
}

export function buildAtlanticMockRoundCall({
  queryResult,
  summary,
  metadata,
  wrapperAddress,
  network = 'sepolia',
  factRegistryMode = 'satellite',
  verifierConfigHash = 0,
  securityBits = 50,
  profile,
  sncast = 'sncast',
  state = {},
}) {
  const normalizedSummary = summaryFromInput(queryResult ?? summary);
  if (!normalizedSummary?.integrityFactHash) {
    throw new Error('Atlantic summary must include integrityFactHash');
  }

  const metadataOutput = metadata?.output ? normalizeFeltArray(metadata.output, 'metadata.output') : undefined;
  const nativeTallyOutput = metadataOutput
    ? extractNativeTallyPublicOutput(metadata.output)
    : undefined;
  const candidates = buildAtlanticFactCandidates({
    summary: normalizedSummary,
    metadata,
  });
  const matchingCandidates = candidates.filter((entry) => entry.matchesIntegrityFact);
  const selectedCandidate = matchingCandidates[0];
  const tallyState = tallyStateFromOutput(nativeTallyOutput, state);
  const blockers = [];
  const warnings = [];

  if (!nativeTallyOutput) {
    blockers.push('metadata output does not contain a native tally public output');
  }
  if (matchingCandidates.length === 0) {
    blockers.push(
      'integrityFactHash did not match supported plain/bootloaded/wrapped bootloaded candidate formulas',
    );
  }
  if (!wrapperAddress) {
    warnings.push('wrapperAddress was not provided; submit command is omitted');
  }
  if (normalizedSummary.status !== 'DONE') {
    warnings.push(`Atlantic query status is ${normalizedSummary.status}`);
  }
  if (normalizedSummary.result !== 'PROOF_VERIFICATION_ON_L2') {
    warnings.push(`Atlantic query result is ${normalizedSummary.result}`);
  }

  const normalizedNetwork = network === 'mainnet' ? 'mainnet' : 'sepolia';
  const registryModeValue = factRegistryMode === 'direct' ? '0' : '1';
  const registryAddress = factRegistryMode === 'direct'
    ? FACT_REGISTRY[normalizedNetwork]
    : SATELLITE[normalizedNetwork];
  const isFactMocked = normalizedSummary.isFactMocked ? '1' : '0';
  const tallyProgramHash = metadata?.child_program_hash ?? normalizedSummary.programHash;
  const currentWrapperSubmitSupported = currentWrapperCanSubmitCandidate(
    selectedCandidate,
    tallyProgramHash,
  );
  if (selectedCandidate && !currentWrapperSubmitSupported) {
    blockers.push(
      'matching integrityFactHash is not directly consumable by current MockAmaciRound tally submit functions; it is registered for a metadata/bootloader-level output',
    );
  }
  const constructorCalldata = [
    '<ADMIN_ADDRESS>',
    registryAddress,
    registryModeValue,
    isFactMocked,
    normalizeHex(verifierConfigHash, 'verifierConfigHash'),
    normalizeHex(securityBits, 'securityBits'),
    '<ADD_NEW_KEY_PROGRAM_HASH>',
    '<PROCESS_MESSAGES_PROGRAM_HASH>',
    '<PROCESS_DEACTIVATE_PROGRAM_HASH>',
    normalizeHex(tallyProgramHash, 'tallyProgramHash'),
    tallyState?.stateCommitment ?? '<INITIAL_STATE_COMMITMENT>',
    '<INITIAL_DEACTIVATE_COMMITMENT>',
    tallyState?.currentTallyCommitment ?? '<INITIAL_TALLY_COMMITMENT>',
  ];

  const selectedVerificationHash = selectedCandidate
    ? bigintToHex(
        calculateVerificationHash(
          selectedCandidate.factHash,
          verifierConfigHash,
          securityBits,
        ),
      )
    : undefined;

  return {
    schema: 'zkstark-amaci.atlantic-mock-round-call.v1',
    network: normalizedNetwork,
    factRegistryMode,
    factRegistryAddress: registryAddress,
    query: {
      id: normalizedSummary.id,
      transactionId: normalizedSummary.transactionId,
      status: normalizedSummary.status,
      result: normalizedSummary.result,
      programHash: normalizedSummary.programHash,
      integrityFactHash: normalizedSummary.integrityFactHash,
      sharpFactHash: normalizedSummary.sharpFactHash,
      isFactMocked: normalizedSummary.isFactMocked,
      isProofMocked: normalizedSummary.isProofMocked,
    },
    metadata: metadata
      ? {
          programHash: metadata.program_hash,
          childProgramHash: metadata.child_program_hash,
          outputFelts: metadataOutput?.length,
          nativeTallyOutputFelts: nativeTallyOutput?.length,
        }
      : undefined,
    tallyState,
    candidates,
    selectedCandidate,
    verificationHash: selectedVerificationHash,
    constructor: {
      contract: 'MockAmaciRound',
      calldata: constructorCalldata,
      declareCommand: `cd contracts && ${sncast}${profile ? ` --profile ${profile}` : ''} declare --contract-name MockAmaciRound`,
      deployCommand: `cd contracts && ${sncast}${profile ? ` --profile ${profile}` : ''} deploy --class-hash <MOCK_AMACI_ROUND_CLASS_HASH> --constructor-calldata ${constructorCalldata.join(' ')}`,
    },
    submit: {
      function: selectedCandidate?.mode
        ? isAtlanticMetadataTallyCandidate(selectedCandidate)
          ? 'submit_tally_atlantic_metadata_fact'
          : {
              plain: 'submit_tally_plain_output_fact',
              bootloaded: 'submit_tally_bootloaded_output_fact',
              wrapped_bootloaded: 'submit_tally_wrapped_bootloaded_output_fact',
            }[selectedCandidate.mode]
        : undefined,
      command: selectedCandidate && tallyState
        ? submitTallyCommand({
            candidate: selectedCandidate,
            wrapperAddress,
            profile,
            sncast,
            state: tallyState,
            tallyProgramHash,
          })
        : undefined,
      supportedByCurrentWrapper: currentWrapperSubmitSupported,
    },
    blockers,
    warnings,
  };
}

export function buildAtlanticMockRoundCallFromFiles({
  queryResultPath,
  summaryPath,
  metadataPath,
  out,
  ...options
}) {
  const queryResult = queryResultPath ? readJson(resolve(queryResultPath), 'Atlantic query result') : undefined;
  const summary = summaryPath ? readJson(resolve(summaryPath), 'Atlantic summary') : undefined;
  const metadata = metadataPath ? readJson(resolve(metadataPath), 'Atlantic metadata') : undefined;
  const result = buildAtlanticMockRoundCall({
    queryResult,
    summary,
    metadata,
    ...options,
  });
  if (out) {
    writeJson(resolve(out), result);
  }
  return result;
}
