import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildFriStepList,
  ceilLog2,
  friStepSum,
  generateStoneParams,
} from '../src/stone-params.mjs';

const baseParams = {
  field: 'PrimeField0',
  stark: {
    fri: {
      fri_step_list: [0, 4, 3],
      last_layer_degree_bound: 64,
      n_queries: 18,
      proof_of_work_bits: 24,
    },
    log_n_cosets: 4,
  },
  use_extension_field: false,
};

test('computes ceil log2 for Stone AIR step counts', () => {
  assert.equal(ceilLog2(1), 0);
  assert.equal(ceilLog2(512), 9);
  assert.equal(ceilLog2(513), 10);
});

test('builds FRI step lists with the requested sum', () => {
  assert.deepEqual(buildFriStepList(7, [0, 4, 3]), [0, 4, 3]);
  assert.deepEqual(buildFriStepList(8, [0, 4, 3]), [0, 4, 4]);
  assert.deepEqual(buildFriStepList(24, [0, 4, 3]), [0, 4, 4, 4, 4, 4, 4]);
});

test('generates Stone params matching a large Cairo AIR degree bound', () => {
  const { params, metadata } = generateStoneParams(baseParams, { n_steps: 2 ** 26 });

  assert.deepEqual(params.stark.fri.fri_step_list, [0, 4, 4, 4, 4, 4, 4]);
  assert.equal(params.channel_hash, 'poseidon3');
  assert.equal(params.commitment_hash, 'keccak256_masked160_lsb');
  assert.equal(params.pow_hash, 'keccak256');
  assert.equal(params.verifier_friendly_channel_updates, true);
  assert.equal(params.verifier_friendly_commitment_hash, 'poseidon3');
  assert.equal(params.n_verifier_friendly_commitment_layers, 20);
  assert.equal(params.statement.page_hash, 'pedersen');
  assert.equal(metadata.profile.name, 'integrity');
  assert.equal(metadata.profile.integrityHasher, 'keccak_160_lsb');
  assert.equal(friStepSum(params.stark.fri.fri_step_list), 24);
  assert.equal(metadata.starkDegreeLog, 30);
  assert.equal(metadata.starkDegreeBound, '1073741824');
  assert.equal(metadata.lastLayerDegreeLog + metadata.friStepSum, metadata.starkDegreeLog);
  assert.equal(params.stark.fri.n_queries, baseParams.stark.fri.n_queries);
  assert.equal(params.stark.fri.proof_of_work_bits, baseParams.stark.fri.proof_of_work_bits);
});

test('can preserve base Stone hash params when requested', () => {
  const { params, metadata } = generateStoneParams(
    baseParams,
    { n_steps: 2 ** 17 },
    { profile: 'base' },
  );

  assert.equal(metadata.profile.name, 'base');
  assert.equal(params.channel_hash, undefined);
  assert.equal(params.commitment_hash, undefined);
  assert.equal(params.n_verifier_friendly_commitment_layers, undefined);
});

test('supports the Integrity blake2s 248-bit LSB hasher profile', () => {
  const { params, metadata } = generateStoneParams(
    baseParams,
    { n_steps: 2 ** 17 },
    { integrityHasher: 'blake2s_248_lsb' },
  );

  assert.equal(params.channel_hash, 'poseidon3');
  assert.equal(params.commitment_hash, 'blake256_masked248_lsb');
  assert.equal(params.pow_hash, 'blake256');
  assert.equal(metadata.profile.integrityHasher, 'blake2s_248_lsb');
});
