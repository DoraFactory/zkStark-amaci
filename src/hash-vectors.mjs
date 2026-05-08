import { joinU128Pair } from './compat/encoding.mjs';

function readU256(value, label) {
  if (!value || typeof value !== 'object') {
    throw new Error(`${label} must be a split u256 object`);
  }
  return joinU128Pair(value.low, value.high, label);
}

function readVector4(value, label) {
  return [
    readU256(value.v0, `${label}.v0`),
    readU256(value.v1, `${label}.v1`),
    readU256(value.v2, `${label}.v2`),
    readU256(value.v3, `${label}.v3`),
  ];
}

function readVector5(value, label) {
  return [
    readU256(value.v0, `${label}.v0`),
    readU256(value.v1, `${label}.v1`),
    readU256(value.v2, `${label}.v2`),
    readU256(value.v3, `${label}.v3`),
    readU256(value.v4, `${label}.v4`),
  ];
}

function readVector10(value, label) {
  return [
    readU256(value.v0, `${label}.v0`),
    readU256(value.v1, `${label}.v1`),
    readU256(value.v2, `${label}.v2`),
    readU256(value.v3, `${label}.v3`),
    readU256(value.v4, `${label}.v4`),
    readU256(value.v5, `${label}.v5`),
    readU256(value.v6, `${label}.v6`),
    readU256(value.v7, `${label}.v7`),
    readU256(value.v8, `${label}.v8`),
    readU256(value.v9, `${label}.v9`),
  ];
}

function vector(id, type, inputs, output) {
  return {
    id,
    type,
    inputs: inputs.map((value) => value.toString()),
    output: output.toString(),
  };
}

function hash2Vector(id, claim) {
  return vector(
    id,
    'poseidon2',
    [readU256(claim.in0, `${id}.in0`), readU256(claim.in1, `${id}.in1`)],
    readU256(claim.out, `${id}.out`),
  );
}

function hash5Vector(id, claim) {
  return vector(id, 'poseidon5', readVector5(claim.inputs, `${id}.inputs`), readU256(claim.out, `${id}.out`));
}

function hash10Vector(id, leaf, claim) {
  return vector(id, 'poseidon10', readVector10(leaf, id), readU256(claim.out.out, `${id}.out.out`));
}

function sha4Vector(id, claim) {
  return vector(id, 'sha256_u256x4_mod_bn254', readVector4(claim.inputs, `${id}.inputs`), readU256(claim.out, `${id}.out`));
}

export function collectTallyHashVectors(programInput) {
  const h = programInput.witness.hashes;
  return [
    hash2Vector('state_commitment', h.state_commitment),
    sha4Vector('input_hash', h.input_hash),
    hash10Vector('state_leaf_0', programInput.witness.state_leaf_0, h.state_leaf_0),
    hash10Vector('state_leaf_1', programInput.witness.state_leaf_1, h.state_leaf_1),
    hash10Vector('state_leaf_2', programInput.witness.state_leaf_2, h.state_leaf_2),
    hash10Vector('state_leaf_3', programInput.witness.state_leaf_3, h.state_leaf_3),
    hash10Vector('state_leaf_4', programInput.witness.state_leaf_4, h.state_leaf_4),
    hash5Vector('state_subroot', h.state_subroot),
    hash5Vector('state_root_from_path', h.state_root_from_path),
    hash5Vector('vote_zero_root', h.vote_zero_root),
    hash5Vector('vote_root_0', h.vote_root_0),
    hash5Vector('vote_root_1', h.vote_root_1),
    hash5Vector('vote_root_2', h.vote_root_2),
    hash5Vector('vote_root_3', h.vote_root_3),
    hash5Vector('vote_root_4', h.vote_root_4),
    hash5Vector('current_results_root', h.current_results_root),
    hash2Vector('current_tally_commitment', h.current_tally_commitment),
    hash5Vector('new_results_root', h.new_results_root),
    hash2Vector('new_tally_commitment', h.new_tally_commitment),
  ];
}
