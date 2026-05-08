# TallyVotes Compatibility Spec

This spec defines the first `zkStark-amaci` target. It is deliberately narrow:
only the existing AMACI `TallyVotes(2, 1, 1)` relation is supported.

## Parameters

| Name | Value |
| --- | --- |
| `stateTreeDepth` | `2` |
| `intStateTreeDepth` | `1` |
| `voteOptionTreeDepth` | `1` |
| `treeArity` | `5` |
| `batchSize` | `5` |
| `numVoteOptions` | `5` |

## Field and Integer Encoding

- Existing AMACI values are interpreted as `uint256`.
- Poseidon inputs are reduced into the BN254 scalar field by the same
  Circom/Rust compatibility path used by the current repo.
- AMACI state leaves contain 10 fields. `Hasher10` is the existing Circom
  composition:

```text
Hasher10(leaf[0..9]) =
  HashLeftRight(
    Hasher5(leaf[0], leaf[1], leaf[2], leaf[3], leaf[4]),
    Hasher5(leaf[5], leaf[6], leaf[7], leaf[8], leaf[9])
  )
```

- SHA-256 inputs are exactly four 32-byte big-endian `uint256` words.
- The SHA-256 digest is interpreted as a big-endian integer and reduced modulo:

```text
21888242871839275222246405745257275088548364400416034343698204186575808495617
```

## Public Input Hash

For `TallyVotes`, the existing on-chain code computes:

```text
packedVals = (numSignUps << 32) + batchNum
inputHash = sha256_uint256_list([
  packedVals,
  stateCommitment,
  currentTallyCommitment,
  newTallyCommitment
]) mod BN254_SCALAR_FIELD
```

`packedVals` unpacking is:

```text
numSignUps = packedVals >> 32
batchNum = packedVals & (2^32 - 1)
```

## Relation

The Stark-compatible implementation must enforce:

- `stateCommitment == Poseidon(stateRoot, stateSalt)`.
- `inputHash` equals the public input hash above.
- `batchNum * batchSize <= numSignUps`.
- The batch AMACI state leaves hash with `Hasher10` to a subroot and that
  subroot is included in `stateRoot` using the provided quinary Merkle path.
- For every state leaf, `votes[i]` hashes to the vote-option root in
  `stateLeaf[i][3]`, except when that field is zero, in which case the expected
  root is `ZeroRoot(voteOptionTreeDepth)`.
- `currentTallyCommitment` is zero for the first batch, otherwise it must equal
  `Poseidon(QuinRoot(currentResults), currentResultsRootSalt)`.
- `newTallyCommitment == Poseidon(QuinRoot(newResults), newResultsRootSalt)`.

`newResults[i]` is:

```text
(isFirstBatch ? 0 : currentResults[i])
+ sum_j votes[j][i] * (votes[j][i] + 10^24)
```

## Canonical Public Output

The Cairo program output is a felt list:

```text
[
  magic,
  version,
  circuit_id,
  state_tree_depth,
  int_state_tree_depth,
  vote_option_tree_depth,
  packed_vals_low128,
  packed_vals_high128,
  state_commitment_low128,
  state_commitment_high128,
  current_tally_commitment_low128,
  current_tally_commitment_high128,
  new_tally_commitment_low128,
  new_tally_commitment_high128,
  input_hash_low128,
  input_hash_high128
]
```

Constants:

```text
magic = 0x4d414349535441524b      // "MACISTARK"
version = 1
circuit_id = 0x414d4143495f54414c4c595f564f544553 // "AMACI_TALLY_VOTES"
```

All 256-bit values split as:

```text
low128 = value mod 2^128
high128 = value >> 128
```

## Integrity Binding

The wrapper contract must bind the proof to:

- a fixed Cairo child program hash,
- the canonical public output above,
- a minimum security-bits threshold,
- the current wrapper state.

When using Integrity, prefer the official helper functions:

- `calculate_fact_hash`
- `calculate_bootloaded_fact_hash`
- `is_fact_hash_valid_with_security`

The JavaScript tool emits the same output list and can calculate development
fact hashes when `starknet.js` is available in the parent repository install.
