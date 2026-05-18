function parseNonNegativeBigInt(value, label) {
  if (typeof value === 'bigint') {
    if (value < 0n) {
      throw new Error(`${label} must be non-negative`);
    }
    return value;
  }

  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a safe non-negative integer`);
    }
    return BigInt(value);
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^(0|[1-9][0-9]*)$/.test(trimmed)) {
      return BigInt(trimmed);
    }
  }

  throw new Error(`${label} must be a non-negative integer`);
}

function assertPowerOfTwo(value, label) {
  if (value <= 0n || (value & (value - 1n)) !== 0n) {
    throw new Error(`${label} must be a positive power of two`);
  }
}

export function ceilLog2(value) {
  const n = parseNonNegativeBigInt(value, 'value');
  if (n <= 1n) {
    return 0;
  }

  return (n - 1n).toString(2).length;
}

export function exactLog2PowerOfTwo(value, label = 'value') {
  const n = parseNonNegativeBigInt(value, label);
  assertPowerOfTwo(n, label);
  return n.toString(2).length - 1;
}

export function friStepSum(friStepList) {
  if (!Array.isArray(friStepList)) {
    throw new Error('fri_step_list must be an array');
  }

  return friStepList.reduce((sum, value, index) => {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`fri_step_list[${index}] must be a non-negative integer`);
    }
    return sum + value;
  }, 0);
}

export function buildFriStepList(targetSum, baseFriStepList = []) {
  if (!Number.isInteger(targetSum) || targetSum < 0) {
    throw new Error('target FRI step sum must be a non-negative integer');
  }

  const steps = baseFriStepList[0] === 0 ? [0] : [];
  let remaining = targetSum;

  while (remaining > 0) {
    if (remaining <= 4) {
      if (remaining === 1 && steps.length > 0) {
        const lastIndex = steps.length - 1;
        if (steps[lastIndex] > 2) {
          steps[lastIndex] -= 1;
          steps.push(2);
          remaining = 0;
          continue;
        }
      }

      steps.push(remaining);
      remaining = 0;
    } else {
      steps.push(4);
      remaining -= 4;
    }
  }

  return steps;
}

const INTEGRITY_HASHERS = Object.freeze({
  keccak_160_lsb: Object.freeze({
    commitmentHash: 'keccak256_masked160_lsb',
    powHash: 'keccak256',
  }),
  blake2s_248_lsb: Object.freeze({
    commitmentHash: 'blake256_masked248_lsb',
    powHash: 'blake256',
  }),
});

function applyIntegrityProfile(params, options = {}) {
  const integrityHasher = options.integrityHasher ?? 'keccak_160_lsb';
  const hasher = INTEGRITY_HASHERS[integrityHasher];
  if (!hasher) {
    throw new Error(
      `unsupported Integrity Stone hasher '${integrityHasher}'; supported: ${Object.keys(
        INTEGRITY_HASHERS,
      ).join(', ')}`,
    );
  }

  const logNCosets = params?.stark?.log_n_cosets;
  if (!Number.isInteger(logNCosets) || logNCosets < 0) {
    throw new Error('stark.log_n_cosets must be a non-negative integer');
  }

  params.channel_hash = 'poseidon3';
  params.commitment_hash = hasher.commitmentHash;
  params.pow_hash = hasher.powHash;
  params.verifier_friendly_channel_updates = true;
  params.verifier_friendly_commitment_hash = 'poseidon3';
  params.n_verifier_friendly_commitment_layers =
    options.nVerifierFriendlyCommitmentLayers ?? logNCosets * 5;
  params.statement = {
    ...(params.statement ?? {}),
    page_hash: 'pedersen',
  };

  return {
    integrityHasher,
    commitmentHash: params.commitment_hash,
    powHash: params.pow_hash,
    channelHash: params.channel_hash,
    verifierFriendlyCommitmentHash: params.verifier_friendly_commitment_hash,
    verifierFriendlyChannelUpdates: params.verifier_friendly_channel_updates,
    nVerifierFriendlyCommitmentLayers: params.n_verifier_friendly_commitment_layers,
  };
}

export function generateStoneParams(baseParams, airPublicInput, options = {}) {
  const nSteps = parseNonNegativeBigInt(airPublicInput.n_steps, 'air_public_input.n_steps');
  if (nSteps === 0n) {
    throw new Error('air_public_input.n_steps must be greater than zero');
  }

  const params = structuredClone(baseParams);
  const fri = params?.stark?.fri;
  if (!fri || typeof fri !== 'object') {
    throw new Error('base params must contain stark.fri');
  }

  const lastLayerDegreeBound = parseNonNegativeBigInt(
    fri.last_layer_degree_bound,
    'stark.fri.last_layer_degree_bound',
  );
  const lastLayerDegreeLog = exactLog2PowerOfTwo(
    lastLayerDegreeBound,
    'stark.fri.last_layer_degree_bound',
  );
  const starkDegreeLog = ceilLog2(nSteps) + 4;
  const targetFriStepSum = starkDegreeLog - lastLayerDegreeLog;

  if (targetFriStepSum < 0) {
    throw new Error(
      `last_layer_degree_bound is too large for n_steps=${nSteps.toString()}`,
    );
  }

  const baseFriStepList = Array.isArray(fri.fri_step_list) ? fri.fri_step_list : [];
  const generatedFriStepList = buildFriStepList(targetFriStepSum, baseFriStepList);
  fri.fri_step_list = generatedFriStepList;
  const profileName = options.profile ?? 'integrity';
  if (profileName !== 'integrity' && profileName !== 'base') {
    throw new Error(`unsupported Stone params profile '${profileName}'`);
  }
  const profile =
    profileName === 'base'
      ? { name: 'base' }
      : { name: 'integrity', ...applyIntegrityProfile(params, options) };

  return {
    params,
    metadata: {
      profile,
      nSteps: nSteps.toString(),
      starkDegreeLog,
      starkDegreeBound: (1n << BigInt(starkDegreeLog)).toString(),
      lastLayerDegreeBound: lastLayerDegreeBound.toString(),
      lastLayerDegreeLog,
      baseFriStepList,
      baseFriStepSum: friStepSum(baseFriStepList),
      friStepList: generatedFriStepList,
      friStepSum: friStepSum(generatedFriStepList),
    },
  };
}
