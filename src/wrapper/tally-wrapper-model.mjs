import { SMALL_TALLY_PARAMS, TREE_ARITY } from '../constants.mjs';
import { parseBigInt } from '../compat/encoding.mjs';
import { canonicalTallyPublicOutput } from '../public-output.mjs';
import {
  calculateBootloadedFactHash,
  calculatePlainFactHash,
  calculateVerificationHash,
} from '../integrity/hashes.mjs';

export class MockIntegrityRegistry {
  #securityByFact = new Map();

  registerFact(factHash, securityBits) {
    const fact = parseBigInt(factHash, 'factHash').toString();
    const bits = Number(parseBigInt(securityBits, 'securityBits'));
    if (!Number.isInteger(bits) || bits < 0) {
      throw new Error('securityBits must be a non-negative integer');
    }
    this.#securityByFact.set(fact, bits);
  }

  isFactHashValidWithSecurity(factHash, minSecurityBits) {
    const fact = parseBigInt(factHash, 'factHash').toString();
    const min = Number(parseBigInt(minSecurityBits, 'minSecurityBits'));
    return (this.#securityByFact.get(fact) ?? -1) >= min;
  }
}

export class TallyVotesStarkWrapperModel {
  constructor({
    integrity,
    tallyProgramHash,
    bootloaderProgramHash,
    verifierConfigHash,
    minSecurityBits,
    packedVals,
    stateCommitment,
    currentTallyCommitment = 0n,
    processedUserCount = 0n,
    params = SMALL_TALLY_PARAMS,
  }) {
    if (!integrity) {
      throw new Error('integrity registry is required');
    }
    this.integrity = integrity;
    this.tallyProgramHash = parseBigInt(tallyProgramHash, 'tallyProgramHash');
    this.bootloaderProgramHash =
      bootloaderProgramHash === undefined
        ? undefined
        : parseBigInt(bootloaderProgramHash, 'bootloaderProgramHash');
    this.verifierConfigHash =
      verifierConfigHash === undefined
        ? undefined
        : parseBigInt(verifierConfigHash, 'verifierConfigHash');
    this.minSecurityBits = Number(parseBigInt(minSecurityBits, 'minSecurityBits'));
    this.packedVals = parseBigInt(packedVals, 'packedVals');
    this.stateCommitment = parseBigInt(stateCommitment, 'stateCommitment');
    this.currentTallyCommitment = parseBigInt(currentTallyCommitment, 'currentTallyCommitment');
    this.processedUserCount = parseBigInt(processedUserCount, 'processedUserCount');
    this.params = params;
  }

  expectedPublicOutput({ newTallyCommitment, inputHash }) {
    return canonicalTallyPublicOutput(
      {
        packedVals: this.packedVals,
        stateCommitment: this.stateCommitment,
        currentTallyCommitment: this.currentTallyCommitment,
        newTallyCommitment: parseBigInt(newTallyCommitment, 'newTallyCommitment'),
        inputHash: parseBigInt(inputHash, 'inputHash'),
      },
      this.params,
    );
  }

  expectedFact({ newTallyCommitment, inputHash }) {
    const publicOutput = this.expectedPublicOutput({ newTallyCommitment, inputHash });
    if (this.bootloaderProgramHash === undefined) {
      const plain = calculatePlainFactHash(this.tallyProgramHash, publicOutput.felts);
      return {
        mode: 'plain',
        publicOutput,
        ...plain,
      };
    }

    const bootloaded = calculateBootloadedFactHash(
      this.bootloaderProgramHash,
      this.tallyProgramHash,
      publicOutput.felts,
    );
    return {
      mode: 'bootloaded',
      publicOutput,
      outputHash: bootloaded.bootloaderOutputHash,
      ...bootloaded,
    };
  }

  submitTallyFact({ newTallyCommitment, inputHash, factHash, verificationHash }) {
    const expected = this.expectedFact({ newTallyCommitment, inputHash });
    const providedFactHash = parseBigInt(factHash, 'factHash');

    if (providedFactHash !== expected.factHash) {
      throw new Error('FACT_HASH_BINDING_MISMATCH');
    }

    if (
      this.verifierConfigHash !== undefined &&
      verificationHash !== undefined
    ) {
      const expectedVerificationHash = calculateVerificationHash(
        expected.factHash,
        this.verifierConfigHash,
        this.minSecurityBits,
      );
      if (parseBigInt(verificationHash, 'verificationHash') !== expectedVerificationHash) {
        throw new Error('VERIFICATION_HASH_MISMATCH');
      }
    }

    if (!this.integrity.isFactHashValidWithSecurity(expected.factHash, this.minSecurityBits)) {
      throw new Error('INVALID_INTEGRITY_FACT');
    }

    this.currentTallyCommitment = parseBigInt(newTallyCommitment, 'newTallyCommitment');
    this.processedUserCount += BigInt(TREE_ARITY ** this.params.intStateTreeDepth);

    return {
      factHash: expected.factHash,
      currentTallyCommitment: this.currentTallyCommitment,
      processedUserCount: this.processedUserCount,
    };
  }
}

