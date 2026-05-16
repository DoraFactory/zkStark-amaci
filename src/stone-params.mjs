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

export function generateStoneParams(baseParams, airPublicInput) {
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

  return {
    params,
    metadata: {
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
