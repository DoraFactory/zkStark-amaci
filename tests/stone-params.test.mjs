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
  assert.equal(friStepSum(params.stark.fri.fri_step_list), 24);
  assert.equal(metadata.starkDegreeLog, 30);
  assert.equal(metadata.starkDegreeBound, '1073741824');
  assert.equal(metadata.lastLayerDegreeLog + metadata.friStepSum, metadata.starkDegreeLog);
  assert.equal(params.stark.fri.n_queries, baseParams.stark.fri.n_queries);
  assert.equal(params.stark.fri.proof_of_work_bits, baseParams.stark.fri.proof_of_work_bits);
});
