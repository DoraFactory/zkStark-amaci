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
const ADD_NEW_KEY_NATIVE_CIRCUIT_ID = 0x414d4143495f4144445f4b45595f4e4154495645n;
const PROCESS_MESSAGES_NATIVE_CIRCUIT_ID = 0x414d4143495f50524f434553535f4d53475f4e4154495645n;
const PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID = 0x414d4143495f50524f434553535f44454143545f4e4154495645n;

const NATIVE_OUTPUT_SPECS = Object.freeze({
  tally: {
    label: 'native-tally-output',
    circuitId: TALLY_VOTES_NATIVE_CIRCUIT_ID,
    outputLength: 12,
  },
  addNewKey: {
    label: 'native-add-new-key-output',
    circuitId: ADD_NEW_KEY_NATIVE_CIRCUIT_ID,
    outputLength: 19,
  },
  processMessages: {
    label: 'native-process-messages-output',
    circuitId: PROCESS_MESSAGES_NATIVE_CIRCUIT_ID,
    outputLength: 16,
  },
  processDeactivate: {
    label: 'native-process-deactivate-output',
    circuitId: PROCESS_DEACTIVATE_NATIVE_CIRCUIT_ID,
    outputLength: 16,
  },
});

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

export function extractNativePublicOutput(values, spec) {
  const felts = normalizeFeltArray(values, 'metadata.output');
  for (let i = 0; i <= felts.length - spec.outputLength; i += 1) {
    if (
      felts[i] === PUBLIC_OUTPUT_MAGIC &&
      felts[i + 1] === NATIVE_PUBLIC_OUTPUT_VERSION &&
      felts[i + 2] === spec.circuitId
    ) {
      return felts.slice(i, i + spec.outputLength);
    }
  }
  return undefined;
}

export function extractNativeTallyPublicOutput(values) {
  return extractNativePublicOutput(values, NATIVE_OUTPUT_SPECS.tally);
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
  const nativeOutputs = metadataOutput
    ? Object.values(NATIVE_OUTPUT_SPECS)
        .map((spec) => {
          const output = extractNativePublicOutput(metadata.output, spec);
          return output
            ? {
                label: spec.label,
                output,
              }
            : undefined;
        })
        .filter(Boolean)
    : [];

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
    ...nativeOutputs,
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
  if (isAtlanticMetadataCandidate(candidate)) {
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
  return isAtlanticMetadataCandidate(candidate);
}

function isAtlanticMetadataCandidate(candidate) {
  return candidate?.mode === 'bootloaded'
    && candidate.outputLabel === 'metadata-output'
    && candidate.childProgramHashRole === 'metadata-program'
    && candidate.bootloaderLabel === 'sharp';
}

function submitCommand({ operation, candidate, wrapperAddress, profile, sncast, state, tallyProgramHash }) {
  if (!candidate || !wrapperAddress) {
    return undefined;
  }
  if (!currentWrapperCanSubmitCandidate(candidate, tallyProgramHash)) {
    return undefined;
  }
  const output = candidate.outputFelts;
  if (operation === 'addNewKey' && isAtlanticMetadataCandidate(candidate)) {
    return sncastInvokeCommand({
      sncast,
      profile,
      contractAddress: wrapperAddress,
      functionName: 'submit_add_new_key_atlantic_metadata_fact',
      calldata: [
        state.keyNullifier,
        state.newStateCommitment,
        candidate.childProgramHash,
        output.length,
        ...output,
        candidate.factHash,
      ],
    });
  }
  if (operation === 'processMessages' && isAtlanticMetadataCandidate(candidate)) {
    return sncastInvokeCommand({
      sncast,
      profile,
      contractAddress: wrapperAddress,
      functionName: 'submit_process_messages_atlantic_metadata_fact',
      calldata: [
        state.currentStateCommitment,
        state.newStateCommitment,
        state.currentDeactivateCommitment,
        candidate.childProgramHash,
        output.length,
        ...output,
        candidate.factHash,
      ],
    });
  }
  if (operation === 'processDeactivate' && isAtlanticMetadataCandidate(candidate)) {
    return sncastInvokeCommand({
      sncast,
      profile,
      contractAddress: wrapperAddress,
      functionName: 'submit_process_deactivate_atlantic_metadata_fact',
      calldata: [
        state.currentDeactivateCommitment,
        state.newDeactivateCommitment,
        state.currentStateCommitment,
        candidate.childProgramHash,
        output.length,
        ...output,
        candidate.factHash,
      ],
    });
  }
  if (operation === 'generic' && isAtlanticMetadataCandidate(candidate)) {
    return sncastInvokeCommand({
      sncast,
      profile,
      contractAddress: wrapperAddress,
      functionName: 'submit_operation_atlantic_metadata_fact',
      calldata: [
        state.operationId,
        state.childProgramHash,
        candidate.childProgramHash,
        output.length,
        ...output,
        candidate.factHash,
      ],
    });
  }
  if (operation === 'addNewKey' && candidate.mode === 'plain') {
    return sncastInvokeCommand({
      sncast,
      profile,
      contractAddress: wrapperAddress,
      functionName: 'submit_add_new_key_fact',
      calldata: [
        state.keyNullifier,
        state.newStateCommitment,
        candidate.outputHash,
        candidate.factHash,
      ],
    });
  }
  if (operation === 'processMessages' && candidate.mode === 'plain') {
    return sncastInvokeCommand({
      sncast,
      profile,
      contractAddress: wrapperAddress,
      functionName: 'submit_process_messages_fact',
      calldata: [
        state.currentStateCommitment,
        state.newStateCommitment,
        state.currentDeactivateCommitment,
        candidate.outputHash,
        candidate.factHash,
      ],
    });
  }
  if (operation === 'processDeactivate' && candidate.mode === 'plain') {
    return sncastInvokeCommand({
      sncast,
      profile,
      contractAddress: wrapperAddress,
      functionName: 'submit_process_deactivate_fact',
      calldata: [
        state.currentDeactivateCommitment,
        state.newDeactivateCommitment,
        state.currentStateCommitment,
        candidate.outputHash,
        candidate.factHash,
      ],
    });
  }
  if (operation !== 'tally') {
    return undefined;
  }
  const currentTallyCommitment = normalizeHex(state.currentTallyCommitment, 'currentTallyCommitment');
  const newTallyCommitment = normalizeHex(state.newTallyCommitment, 'newTallyCommitment');
  const stateCommitment = normalizeHex(state.stateCommitment, 'stateCommitment');
  if (operation === 'tally' && isAtlanticMetadataTallyCandidate(candidate)) {
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

function operationFromInput(operation = 'tally') {
  const normalized = String(operation).trim().toLowerCase();
  if (normalized === 'tally' || normalized === 'tally-native') {
    return 'tally';
  }
  if (normalized === 'add-new-key' || normalized === 'addnewkey' || normalized === 'add-new-key-native') {
    return 'addNewKey';
  }
  if (
    normalized === 'process-messages' ||
    normalized === 'processmessages' ||
    normalized === 'process-messages-boundary-native'
  ) {
    return 'processMessages';
  }
  if (
    normalized === 'process-deactivate' ||
    normalized === 'processdeactivate' ||
    normalized === 'process-deactivate-boundary-native'
  ) {
    return 'processDeactivate';
  }
  if (normalized === 'generic' || normalized === 'operation') {
    return 'generic';
  }
  throw new Error(`unsupported operation: ${operation}`);
}

function operationNativeOutput(operation, metadataOutput) {
  if (!metadataOutput || operation === 'generic') {
    return undefined;
  }
  const spec = NATIVE_OUTPUT_SPECS[operation];
  return spec ? extractNativePublicOutput(metadataOutput, spec) : undefined;
}

function operationStateFromOutput(operation, nativeOutput, overrides = {}, operationProgramHash) {
  if (operation === 'tally') {
    return tallyStateFromOutput(nativeOutput, overrides);
  }
  if (operation === 'addNewKey') {
    if (!nativeOutput) {
      return undefined;
    }
    return {
      keyNullifier: overrides.keyNullifier
        ? normalizeHex(overrides.keyNullifier, 'keyNullifier')
        : bigintToHex(nativeOutput[8]),
      newStateCommitment: overrides.newStateCommitment
        ? normalizeHex(overrides.newStateCommitment, 'newStateCommitment')
        : undefined,
    };
  }
  if (operation === 'processMessages') {
    if (!nativeOutput) {
      return undefined;
    }
    return {
      currentStateCommitment: overrides.currentStateCommitment
        ? normalizeHex(overrides.currentStateCommitment, 'currentStateCommitment')
        : bigintToHex(nativeOutput[11]),
      newStateCommitment: overrides.newStateCommitment
        ? normalizeHex(overrides.newStateCommitment, 'newStateCommitment')
        : bigintToHex(nativeOutput[12]),
      currentDeactivateCommitment: overrides.currentDeactivateCommitment
        ? normalizeHex(overrides.currentDeactivateCommitment, 'currentDeactivateCommitment')
        : bigintToHex(nativeOutput[13]),
    };
  }
  if (operation === 'processDeactivate') {
    if (!nativeOutput) {
      return undefined;
    }
    return {
      currentDeactivateCommitment: overrides.currentDeactivateCommitment
        ? normalizeHex(overrides.currentDeactivateCommitment, 'currentDeactivateCommitment')
        : bigintToHex(nativeOutput[11]),
      newDeactivateCommitment: overrides.newDeactivateCommitment
        ? normalizeHex(overrides.newDeactivateCommitment, 'newDeactivateCommitment')
        : bigintToHex(nativeOutput[12]),
      currentStateCommitment: overrides.currentStateCommitment || overrides.stateCommitment
        ? normalizeHex(
            overrides.currentStateCommitment ?? overrides.stateCommitment,
            'currentStateCommitment',
          )
        : undefined,
    };
  }
  if (operation === 'generic') {
    return {
      operationId: normalizeHex(overrides.operationId ?? 0, 'operationId'),
      childProgramHash: normalizeHex(
        overrides.childProgramHash ?? operationProgramHash,
        'childProgramHash',
      ),
    };
  }
  return undefined;
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
  operation = 'tally',
}) {
  const normalizedOperation = operationFromInput(operation);
  const normalizedSummary = summaryFromInput(queryResult ?? summary);
  if (!normalizedSummary?.integrityFactHash) {
    throw new Error('Atlantic summary must include integrityFactHash');
  }

  const metadataOutput = metadata?.output ? normalizeFeltArray(metadata.output, 'metadata.output') : undefined;
  const nativeOutput = metadataOutput
    ? operationNativeOutput(normalizedOperation, metadata.output)
    : undefined;
  const candidates = buildAtlanticFactCandidates({
    summary: normalizedSummary,
    metadata,
  });
  const matchingCandidates = candidates.filter((entry) => entry.matchesIntegrityFact);
  const selectedCandidate = matchingCandidates[0];
  const operationProgramHash = metadata?.child_program_hash ?? normalizedSummary.programHash;
  const operationState = operationStateFromOutput(
    normalizedOperation,
    nativeOutput,
    state,
    operationProgramHash,
  );
  const blockers = [];
  const warnings = [];

  if (normalizedOperation !== 'generic' && !nativeOutput) {
    blockers.push(`metadata output does not contain a native ${operation} public output`);
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
  const operationProgramHashHex = normalizeHex(operationProgramHash, 'operationProgramHash');
  const addNewKeyProgramHash = normalizedOperation === 'addNewKey'
    ? operationProgramHashHex
    : '<ADD_NEW_KEY_PROGRAM_HASH>';
  const processMessagesProgramHash = normalizedOperation === 'processMessages'
    ? operationProgramHashHex
    : '<PROCESS_MESSAGES_PROGRAM_HASH>';
  const processDeactivateProgramHash = normalizedOperation === 'processDeactivate'
    ? operationProgramHashHex
    : '<PROCESS_DEACTIVATE_PROGRAM_HASH>';
  const tallyProgramHash = normalizedOperation === 'tally'
    ? operationProgramHashHex
    : '<TALLY_PROGRAM_HASH>';
  const currentWrapperSubmitSupported = currentWrapperCanSubmitCandidate(
    selectedCandidate,
    operationProgramHash,
  );
  if (selectedCandidate && !currentWrapperSubmitSupported) {
    blockers.push(
      'matching integrityFactHash is not directly consumable by current MockAmaciRound tally submit functions; it is registered for a metadata/bootloader-level output',
    );
  }
  if (normalizedOperation === 'addNewKey' && !operationState?.newStateCommitment) {
    blockers.push('add-new-key submission requires --new-state-commitment');
  }
  if (normalizedOperation === 'processDeactivate' && !operationState?.currentStateCommitment) {
    blockers.push('process-deactivate submission requires --state-commitment');
  }
  if (normalizedOperation === 'generic' && !operationState?.operationId) {
    blockers.push('generic operation submission requires --operation-id');
  }
  const constructorInitialState = normalizedOperation === 'tally'
    ? operationState?.stateCommitment
    : operationState?.currentStateCommitment;
  const constructorInitialTally = normalizedOperation === 'tally'
    ? operationState?.currentTallyCommitment
    : undefined;
  const constructorCalldata = [
    '<ADMIN_ADDRESS>',
    registryAddress,
    registryModeValue,
    isFactMocked,
    normalizeHex(verifierConfigHash, 'verifierConfigHash'),
    normalizeHex(securityBits, 'securityBits'),
    addNewKeyProgramHash,
    processMessagesProgramHash,
    processDeactivateProgramHash,
    tallyProgramHash,
    constructorInitialState ?? '<INITIAL_STATE_COMMITMENT>',
    '<INITIAL_DEACTIVATE_COMMITMENT>',
    constructorInitialTally ?? '<INITIAL_TALLY_COMMITMENT>',
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
    operation: normalizedOperation,
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
          nativeOutputFelts: nativeOutput?.length,
        }
      : undefined,
    tallyState: normalizedOperation === 'tally' ? operationState : undefined,
    operationState,
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
        ? isAtlanticMetadataCandidate(selectedCandidate)
          ? {
              tally: 'submit_tally_atlantic_metadata_fact',
              addNewKey: 'submit_add_new_key_atlantic_metadata_fact',
              processMessages: 'submit_process_messages_atlantic_metadata_fact',
              processDeactivate: 'submit_process_deactivate_atlantic_metadata_fact',
              generic: 'submit_operation_atlantic_metadata_fact',
            }[normalizedOperation]
          : normalizedOperation === 'tally'
            ? {
              plain: 'submit_tally_plain_output_fact',
              bootloaded: 'submit_tally_bootloaded_output_fact',
              wrapped_bootloaded: 'submit_tally_wrapped_bootloaded_output_fact',
            }[selectedCandidate.mode]
            : {
              addNewKey: { plain: 'submit_add_new_key_fact' }[selectedCandidate.mode],
              processMessages: { plain: 'submit_process_messages_fact' }[selectedCandidate.mode],
              processDeactivate: { plain: 'submit_process_deactivate_fact' }[
                selectedCandidate.mode
              ],
            }[normalizedOperation]
        : undefined,
      command: selectedCandidate && operationState && blockers.length === 0
        ? submitCommand({
            operation: normalizedOperation,
            candidate: selectedCandidate,
            wrapperAddress,
            profile,
            sncast,
            state: operationState,
            tallyProgramHash: operationProgramHash,
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
