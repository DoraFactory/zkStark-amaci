import { bigintToHex, splitU256ToU128 } from './encoding.mjs';
import {
  buildBabyjubScalarMulTranscript,
  buildBabyjubPoseidonSignatureWitness,
  buildEcdhSharedKeyWitness,
  verifyBabyjubPoseidonSignatureWitness,
  verifyBabyjubScalarMulTranscript,
} from './babyjub.mjs';

function splitObject(value, label) {
  const { low, high } = splitU256ToU128(value, label);
  return {
    low: low.toString(),
    high: high.toString(),
  };
}

function splitVector2(values, label) {
  if (!Array.isArray(values) || values.length !== 2) {
    throw new Error(`${label} must contain two values`);
  }
  return {
    v0: splitObject(values[0], `${label}[0]`),
    v1: splitObject(values[1], `${label}[1]`),
  };
}

function splitStep(step, label) {
  return {
    bit: splitObject(step.bit, `${label}.bit`),
    sum: splitVector2(step.sum, `${label}.sum`),
    next_acc: splitVector2(step.nextAcc, `${label}.nextAcc`),
    next_exp: splitVector2(step.nextExp, `${label}.nextExp`),
  };
}

export function buildCairoBabyjubScalarMulInput(rawInput) {
  const witness = rawInput.steps
    ? rawInput
    : buildBabyjubScalarMulTranscript(rawInput.base, rawInput.scalar);
  const expected = verifyBabyjubScalarMulTranscript(witness);

  return {
    expected,
    program_input: {
      witness: {
        scalar: splitObject(witness.scalar, 'scalar'),
        base: splitVector2(witness.base, 'base'),
        expected: splitVector2(expected, 'expected'),
        steps: witness.steps.map((step, index) => splitStep(step, `steps[${index}]`)),
      },
    },
    full_witness: witness,
  };
}

export function buildCairoEcdhSharedKeyInput(rawInput) {
  const witness = rawInput.steps
    ? rawInput
    : buildEcdhSharedKeyWitness(rawInput.privKey, rawInput.pubKey);
  return buildCairoBabyjubScalarMulInput(witness);
}

function splitSignatureWitness(witness) {
  return {
    pub_key_x2: splitVector2(witness.pubKeyX2, 'pubKeyX2'),
    pub_key_x4: splitVector2(witness.pubKeyX4, 'pubKeyX4'),
    pub_key_x8: splitVector2(witness.pubKeyX8, 'pubKeyX8'),
    s_base8: buildCairoBabyjubScalarMulInput(witness.sBase8).program_input.witness,
    h_pub_key_x8: buildCairoBabyjubScalarMulInput(witness.hPubKeyX8).program_input.witness,
    right: splitVector2(witness.right, 'right'),
  };
}

export function buildCairoBabyjubPoseidonSignatureInput(rawInput) {
  const witness = rawInput.sBase8
    ? rawInput
    : buildBabyjubPoseidonSignatureWitness(rawInput);
  const valid = verifyBabyjubPoseidonSignatureWitness(witness);

  return {
    valid,
    program_input: {
      pub_key: splitVector2(witness.pubKey, 'pubKey'),
      r8: splitVector2(witness.r8, 'r8'),
      s: splitObject(witness.s, 's'),
      preimage: {
        v0: splitObject(witness.preimage[0], 'preimage[0]'),
        v1: splitObject(witness.preimage[1], 'preimage[1]'),
        v2: splitObject(witness.preimage[2], 'preimage[2]'),
      },
      witness: splitSignatureWitness(witness),
    },
    expected_output: {
      valid: splitObject(valid, 'valid'),
    },
    full_witness: witness,
  };
}

function pushU256(args, value) {
  args.push(value.low, value.high);
}

function pushVector2(args, value) {
  pushU256(args, value.v0);
  pushU256(args, value.v1);
}

function pushBabyjubStep(args, value) {
  pushU256(args, value.bit);
  pushVector2(args, value.sum);
  pushVector2(args, value.next_acc);
  pushVector2(args, value.next_exp);
}

export function serializeCairoBabyjubScalarMulExecutableArgs(cairoInput) {
  const args = [];
  const { witness } = cairoInput.program_input;
  pushU256(args, witness.scalar);
  pushVector2(args, witness.base);
  pushVector2(args, witness.expected);
  args.push(BigInt(witness.steps.length));
  for (const step of witness.steps) {
    pushBabyjubStep(args, step);
  }
  return args.map((value) => bigintToHex(value));
}

function pushU256x3(args, value) {
  pushU256(args, value.v0);
  pushU256(args, value.v1);
  pushU256(args, value.v2);
}

function pushBabyjubScalarMulWitness(args, witness) {
  pushU256(args, witness.scalar);
  pushVector2(args, witness.base);
  pushVector2(args, witness.expected);
  args.push(BigInt(witness.steps.length));
  for (const step of witness.steps) {
    pushBabyjubStep(args, step);
  }
}

function pushBabyjubPoseidonSignatureWitness(args, witness) {
  pushVector2(args, witness.pub_key_x2);
  pushVector2(args, witness.pub_key_x4);
  pushVector2(args, witness.pub_key_x8);
  pushBabyjubScalarMulWitness(args, witness.s_base8);
  pushBabyjubScalarMulWitness(args, witness.h_pub_key_x8);
  pushVector2(args, witness.right);
}

export function serializeCairoBabyjubPoseidonSignatureExecutableArgs(cairoInput) {
  const args = [];
  const { pub_key, r8, s, preimage, witness } = cairoInput.program_input;
  pushVector2(args, pub_key);
  pushVector2(args, r8);
  pushU256(args, s);
  pushU256x3(args, preimage);
  pushBabyjubPoseidonSignatureWitness(args, witness);
  return args.map((value) => bigintToHex(value));
}
