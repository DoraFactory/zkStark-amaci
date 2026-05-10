# ProcessDeactivateMessages Compatibility Spec

This document describes the current Cairo compatibility target for AMACI
`ProcessDeactivateMessages(stateTreeDepth=2, batchSize=5)`. The deactivate
tree depth is fixed to `stateTreeDepth + 2 = 4`.

The goal is semantic compatibility with the existing Circom circuit, not a
post-quantum redesign of the AMACI cryptographic internals.

## Parameters

| Name | Value |
| --- | --- |
| `stateTreeDepth` | `2` |
| `deactivateTreeDepth` | `4` |
| `batchSize` | `5` |
| `treeArity` | `5` |
| `messageLength` | `10` |

## Public Fields

The canonical public output binds these fields:

- `newDeactivateRoot`
- `coordPubKeyHash = Poseidon(coordPubKey[0], coordPubKey[1])`
- `batchStartHash`
- `batchEndHash`
- `currentDeactivateCommitment`
- `newDeactivateCommitment`
- `currentStateRoot`
- `expectedPollId`
- `inputHash`

All 256-bit public values are emitted as fixed `low128, high128` felt pairs.
The public-output prefix is:

```text
magic, version, circuit_id,
state_tree_depth, deactivate_tree_depth, message_batch_size
```

## Public Input Hash

The input hash follows the existing Circom `Sha256Hasher(8)` shape:

```text
inputHash = Sha256Hasher(8)(
  newDeactivateRoot,
  coordPubKeyHash,
  batchStartHash,
  batchEndHash,
  currentDeactivateCommitment,
  newDeactivateCommitment,
  currentStateRoot,
  expectedPollId
) mod BN254_SCALAR_FIELD
```

Each SHA-256 word is encoded as a 32-byte big-endian unsigned integer, matching
the existing AMACI/Circom bit order.

## Deactivate Message Hash Chain

Each non-empty deactivate message advances the hash chain with:

```text
messageHash = Hasher13([
  msg[0], msg[1], msg[2], msg[3], msg[4],
  msg[5], msg[6], msg[7], msg[8], msg[9],
  encPubKey[0], encPubKey[1],
  previousHash
])
```

Unlike `ProcessMessages`, an empty deactivate message is identified by
`msg[0] == 0`:

```text
nextHash = previousHash if msg[0] == 0
nextHash = messageHash otherwise
```

The boundary relation enforces that the chain starts at `batchStartHash` and
ends at `batchEndHash`.

## Commitments

The boundary relation enforces:

```text
currentDeactivateCommitment =
  Poseidon(currentActiveStateRoot, currentDeactivateRoot)

newDeactivateCommitment =
  Poseidon(newActiveStateRoot, newDeactivateRoot)
```

`newDeactivateCommitment` is checked by the stateful relation after chaining
all five `ProcessDeactivateOne` witnesses.

## ProcessDeactivateOne Relation

Each non-empty message is bound to one `ProcessDeactivateOne` witness. The
current Cairo migration verifies:

- `coordPrivKey * Base8 == coordPubKey` at the batch level.
- `coordPrivKey * encPubKey_i == sharedKey_i` for each non-empty message.
- `PoseidonDecryptWithoutCheck(7)(msg_i, sharedKey_i)` matches the command
  fields inside `processOneWitnesses[i]`.
- `packedCommand[0]` unpacks to `cmdPollId` and `cmdStateIndex`.
- BabyJubJub EdDSA-Poseidon verifies against the state leaf public key.
- The state leaf is included in `currentStateRoot`.
- The current active-state leaf is included in `currentActiveStateRoot`.
- The deactivate leaf is inserted at `deactivateIndex0 + i` in the depth-4
  deactivate tree.
- `ElGamalDecrypt(stateLeaf.c1, stateLeaf.c2, coordPrivKey)` binds the current
  active-state parity.
- `ElGamalDecrypt(c1, c2, coordPrivKey)` binds the new deactivate ciphertext
  parity.
- `newActiveState` is non-zero.

The batch state-transition executable chains five witnesses in forward order:

```text
activeRoot_0 = currentActiveStateRoot
deactivateRoot_0 = currentDeactivateRoot

for i in 0..4:
  witness_i.currentActiveStateRoot == activeRoot_i
  witness_i.currentDeactivateRoot == deactivateRoot_i
  witness_i.deactivateIndex == deactivateIndex0 + i
  activeRoot_{i+1}, deactivateRoot_{i+1} = ProcessDeactivateOne(witness_i)
```

The final `deactivateRoot_5` must equal public `newDeactivateRoot`, and
`Poseidon(activeRoot_5, deactivateRoot_5)` must equal
`newDeactivateCommitment`.

## Split Proof Path

For dense batches, the migration also exposes
`process_deactivate_message_step`. This executable proves one deactivate
message slot with public output containing:

- `messageIndex`
- `deactivateIndex`
- `coordPubKeyHash`
- `previousMessageHash`
- `nextMessageHash`
- `currentActiveStateRoot`
- `currentDeactivateRoot`
- `newActiveStateRoot`
- `newDeactivateRoot`
- `currentDeactivateCommitment`
- `newDeactivateCommitment`
- `currentStateRoot`
- `expectedPollId`

The relation checks:

- `coordPrivKey` derives the boundary `coordPubKey`, and
  `coordPubKeyHash == Poseidon(coordPubKey[0], coordPubKey[1])`.
- The supplied `msg[10]` and `encPubKey[2]` advance
  `previousMessageHash -> nextMessageHash` with the same empty-message rule as
  the boundary.
- Non-empty messages decrypt with the ECDH shared key and match the
  `ProcessDeactivateOne` command fields.
- `ProcessDeactivateOne` maps
  `(currentActiveStateRoot, currentDeactivateRoot)` to
  `(newActiveStateRoot, newDeactivateRoot)` at the public `deactivateIndex`.
- `currentDeactivateCommitment` opens to the current active/deactivate roots,
  and `newDeactivateCommitment` opens to the new active/deactivate roots.

The intended proof composition is:

```text
1 boundary proof
5 process-deactivate-step proofs
```

A wrapper or off-chain checker must chain the public outputs:

```text
boundary.batchStartHash == step0.previousMessageHash
step0.nextMessageHash == step1.previousMessageHash
...
step4.nextMessageHash == boundary.batchEndHash

boundary.currentDeactivateCommitment == step0.currentDeactivateCommitment
boundary.newDeactivateCommitment == step4.newDeactivateCommitment
boundary.newDeactivateRoot == step4.newDeactivateRoot

step0.newActiveStateRoot == step1.currentActiveStateRoot
step0.newDeactivateRoot == step1.currentDeactivateRoot
...
step3.newActiveStateRoot == step4.currentActiveStateRoot
step3.newDeactivateRoot == step4.currentDeactivateRoot

step1.deactivateIndex == step0.deactivateIndex + 1
...
step4.deactivateIndex == step3.deactivateIndex + 1
```

The split path lowers peak prover memory by proving one deactivate slot at a
time, but the Starknet wrapper that verifies all six facts and enforces this
chaining is still pending.

## Empty Slots

For deactivate batches, empty slots are keyed by `msg[0] == 0`. The stateful
relation also requires the matching `ProcessDeactivateOne` witness to carry
`isEmptyMsg == 1`. Empty slots do not advance the public message hash chain.

## Starknet Wrapper Binding

The intended Starknet wrapper should bind an Integrity fact to:

```text
programHash(process_deactivate_messages_stateful)
canonicalProcessDeactivatePublicOutput(publicFields)
```

The wrapper state checks should include:

- `currentDeactivateCommitment` equals the wrapper's stored deactivate
  commitment.
- `currentStateRoot` equals the wrapper's stored state root when tracked.
- the submitted fact hash is registered in Integrity with enough security
  bits.
- optional `verificationHash` matches the configured Integrity verifier
  metadata.

After a valid submission, the wrapper updates the stored deactivate commitment
to `newDeactivateCommitment`.

## Current Limits

- Only `stateTreeDepth=2`, `deactivateTreeDepth=4`, and `batchSize=5` are
  implemented.
- Current tests use synthetic compatibility fixtures. Real operator fixture
  cross-checking is still pending.
- This is a Circom-to-Cairo program migration of the current AMACI logic. It
  does not replace BabyJubJub, EdDSA-Poseidon, ElGamal, or Poseidon with
  post-quantum protocol primitives.
- Full STARK proof generation has not been completed on the current macOS/arm64
  machine; Linux/amd64 proof benchmarking is still required.
