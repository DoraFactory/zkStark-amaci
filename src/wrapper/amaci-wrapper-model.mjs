import { parseBigInt } from '../compat/encoding.mjs';
import {
  canonicalAddNewKeyPublicOutput,
  canonicalProcessDeactivatePublicOutput,
  canonicalProcessMessagesPublicOutput,
  canonicalTallyPublicOutput,
} from '../public-output.mjs';
import {
  calculateBootloadedFactHash,
  calculatePlainFactHash,
  calculateVerificationHash,
} from '../integrity/hashes.mjs';

const CIRCUIT_BUILDERS = Object.freeze({
  tally: canonicalTallyPublicOutput,
  processMessages: canonicalProcessMessagesPublicOutput,
  addNewKey: canonicalAddNewKeyPublicOutput,
  processDeactivate: canonicalProcessDeactivatePublicOutput,
});

function normalizeCircuit(circuit) {
  if (!CIRCUIT_BUILDERS[circuit]) {
    throw new Error(`unsupported circuit: ${circuit}`);
  }
  return circuit;
}

function parseOptional(value, label) {
  return value === undefined ? undefined : parseBigInt(value, label);
}

export class AmaciStarkFactBindingModel {
  constructor({
    integrity,
    programHashes,
    bootloaderProgramHash,
    verifierConfigHash,
    minSecurityBits,
  }) {
    if (!integrity) {
      throw new Error('integrity registry is required');
    }
    this.integrity = integrity;
    this.programHashes = Object.fromEntries(
      Object.entries(programHashes ?? {}).map(([key, value]) => [
        normalizeCircuit(key),
        parseBigInt(value, `${key}.programHash`),
      ]),
    );
    this.bootloaderProgramHash = parseOptional(bootloaderProgramHash, 'bootloaderProgramHash');
    this.verifierConfigHash = parseOptional(verifierConfigHash, 'verifierConfigHash');
    this.minSecurityBits = Number(parseBigInt(minSecurityBits, 'minSecurityBits'));
  }

  publicOutputFor(circuit, fields, params) {
    return CIRCUIT_BUILDERS[normalizeCircuit(circuit)](fields, params);
  }

  expectedFact(circuit, fields, params) {
    const normalized = normalizeCircuit(circuit);
    const programHash = this.programHashes[normalized];
    if (programHash === undefined) {
      throw new Error(`missing program hash for ${normalized}`);
    }
    const publicOutput = this.publicOutputFor(normalized, fields, params);

    if (this.bootloaderProgramHash === undefined) {
      const plain = calculatePlainFactHash(programHash, publicOutput.felts);
      return { mode: 'plain', publicOutput, outputHash: plain.outputHash, ...plain };
    }

    const bootloaded = calculateBootloadedFactHash(
      this.bootloaderProgramHash,
      programHash,
      publicOutput.felts,
    );
    return {
      mode: 'bootloaded',
      publicOutput,
      outputHash: bootloaded.bootloaderOutputHash,
      ...bootloaded,
    };
  }

  assertValidFact(circuit, fields, params, { factHash, verificationHash }) {
    const expected = this.expectedFact(circuit, fields, params);
    if (parseBigInt(factHash, 'factHash') !== expected.factHash) {
      throw new Error('FACT_HASH_BINDING_MISMATCH');
    }

    if (this.verifierConfigHash !== undefined && verificationHash !== undefined) {
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

    return expected;
  }
}

export class AmaciStateWrapperModel extends AmaciStarkFactBindingModel {
  constructor({
    stateCommitment,
    deactivateCommitment,
    currentTallyCommitment = 0n,
    currentStateRoot,
    seenNullifiers,
    ...base
  }) {
    super(base);
    this.stateCommitment = parseOptional(stateCommitment, 'stateCommitment');
    this.deactivateCommitment = parseOptional(deactivateCommitment, 'deactivateCommitment');
    this.currentTallyCommitment = parseBigInt(currentTallyCommitment, 'currentTallyCommitment');
    this.currentStateRoot = parseOptional(currentStateRoot, 'currentStateRoot');
    this.seenNullifiers = new Set(
      [...(seenNullifiers ?? [])].map((value) => parseBigInt(value, 'seenNullifier').toString()),
    );
  }

  submitTally({ fields, params, factHash, verificationHash }) {
    if (
      this.stateCommitment !== undefined &&
      parseBigInt(fields.stateCommitment, 'stateCommitment') !== this.stateCommitment
    ) {
      throw new Error('STATE_COMMITMENT_MISMATCH');
    }
    if (
      parseBigInt(fields.currentTallyCommitment, 'currentTallyCommitment') !==
      this.currentTallyCommitment
    ) {
      throw new Error('CURRENT_TALLY_COMMITMENT_MISMATCH');
    }
    const fact = this.assertValidFact('tally', fields, params, { factHash, verificationHash });
    this.currentTallyCommitment = parseBigInt(fields.newTallyCommitment, 'newTallyCommitment');
    return { factHash: fact.factHash, currentTallyCommitment: this.currentTallyCommitment };
  }

  submitProcessMessages({ fields, params, factHash, verificationHash }) {
    if (
      this.stateCommitment !== undefined &&
      parseBigInt(fields.currentStateCommitment, 'currentStateCommitment') !==
        this.stateCommitment
    ) {
      throw new Error('CURRENT_STATE_COMMITMENT_MISMATCH');
    }
    if (
      this.deactivateCommitment !== undefined &&
      parseBigInt(fields.deactivateCommitment, 'deactivateCommitment') !==
        this.deactivateCommitment
    ) {
      throw new Error('DEACTIVATE_COMMITMENT_MISMATCH');
    }
    const fact = this.assertValidFact('processMessages', fields, params, {
      factHash,
      verificationHash,
    });
    this.stateCommitment = parseBigInt(fields.newStateCommitment, 'newStateCommitment');
    return { factHash: fact.factHash, stateCommitment: this.stateCommitment };
  }

  submitAddNewKey({ fields, params, factHash, verificationHash }) {
    const nullifier = parseBigInt(fields.nullifier, 'nullifier').toString();
    if (this.seenNullifiers.has(nullifier)) {
      throw new Error('NULLIFIER_ALREADY_USED');
    }
    const fact = this.assertValidFact('addNewKey', fields, params, { factHash, verificationHash });
    this.seenNullifiers.add(nullifier);
    return { factHash: fact.factHash, nullifier: parseBigInt(fields.nullifier, 'nullifier') };
  }

  submitProcessDeactivate({ fields, params, factHash, verificationHash }) {
    if (
      this.deactivateCommitment !== undefined &&
      parseBigInt(fields.currentDeactivateCommitment, 'currentDeactivateCommitment') !==
        this.deactivateCommitment
    ) {
      throw new Error('CURRENT_DEACTIVATE_COMMITMENT_MISMATCH');
    }
    if (
      this.currentStateRoot !== undefined &&
      parseBigInt(fields.currentStateRoot, 'currentStateRoot') !== this.currentStateRoot
    ) {
      throw new Error('CURRENT_STATE_ROOT_MISMATCH');
    }
    const fact = this.assertValidFact('processDeactivate', fields, params, {
      factHash,
      verificationHash,
    });
    this.deactivateCommitment = parseBigInt(fields.newDeactivateCommitment, 'newDeactivateCommitment');
    return { factHash: fact.factHash, deactivateCommitment: this.deactivateCommitment };
  }
}
