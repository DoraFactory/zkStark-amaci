# ProcessMessages Compatibility Spec

This spec defines the next `zkStark-amaci` migration target. The current
implementation step is deliberately narrower than the full relation: it locks
and implements the public-input contract and message-hash chain for AMACI
`ProcessMessages(2, 1, 5)`.

## Parameters

| Name | Value |
| --- | --- |
| `stateTreeDepth` | `2` |
| `voteOptionTreeDepth` | `1` |
| `batchSize` | `5` |
| `treeArity` | `5` |
| `messageLength` | `10` |

The upstream aMACI `ProcessMessages` template takes
`stateTreeDepth`, `voteOptionTreeDepth`, and `batchSize`.

## Packed Values

The Circom `ProcessMessagesInputHasher` uses `UnpackElement(3)`:

```text
packedVals =
  (isQuadraticCost << 64)
  + (numSignUps << 32)
  + maxVoteOptions
```

Constraints:

- `isQuadraticCost` is `0` or `1`.
- `maxVoteOptions <= 5^voteOptionTreeDepth`.
- `numSignUps <= 5^stateTreeDepth`.

## Public Input Hash

The public input hash is:

```text
coordPubKeyHash = Poseidon(coordPubKey[0], coordPubKey[1])

inputHash = sha256([
  packedVals,
  coordPubKeyHash,
  batchStartHash,
  batchEndHash,
  currentStateCommitment,
  newStateCommitment,
  deactivateCommitment,
  expectedPollId
]) mod BN254_SCALAR_FIELD
```

SHA-256 inputs are eight 32-byte big-endian `uint256` words, matching the
existing Circom `Sha256Hasher(8)` bit order.

## Message Hash Chain

Each message chain step is:

```text
messageHash = Hasher13([
  msg[0], msg[1], msg[2], msg[3], msg[4],
  msg[5], msg[6], msg[7], msg[8], msg[9],
  encPubKey[0], encPubKey[1],
  previousHash
])
```

If `encPubKey[0] == 0`, the message is treated as empty and the chain does
not advance:

```text
nextHash = previousHash
```

Otherwise:

```text
nextHash = messageHash
```

The public-boundary executable enforces that the chain starts at
`batchStartHash` and ends at `batchEndHash`.

## Commitments

The public-boundary implementation enforces:

- `currentStateCommitment == Poseidon(currentStateRoot, currentStateSalt)`.
- `deactivateCommitment == Poseidon(activeStateRoot, deactivateRoot)`.
- `newStateCommitment == Poseidon(newStateRoot, newStateSalt)` when a
  `newStateRoot` is supplied to the JavaScript evaluator.

The full Cairo relation now has command decryption, command extraction, ECDH
binding, coordinator public-key binding, and BabyJubJub signature verification
for the fixed five-message batch.

## ProcessOne State Transition Slice

The current migration also implements the first `ProcessOne` state-transition
slice for `stateTreeDepth = 2` and `voteOptionTreeDepth = 1`. This now includes
Poseidon command decryption from a supplied `sharedKey`, plus the deterministic
parts of `MessageValidator` and `StateLeafTransformer`. ECDH is enforced in the
stateful ECDH path, and `process_one_with_signature` /
`process_one_with_ecdh_signature` derive `isSignatureValid` inside Cairo for a
single message. The five-message state-transition witness also binds
`isDecryptionActive` to the AMACI `ElGamalDecrypt()` active-state parity.
`process_messages_stateful_with_ecdh_signature` composes the same signature
check across all five message slots.

Inputs:

- `isQuadraticCost`
- `numSignUps`
- `maxVoteOptions`
- `expectedPollId`
- `isSignatureValid`
- `isDecryptionActive`
- `msg[10]`
- `sharedKey[2]`
- `decryptedCommand[7]`
- `packedCommand[3]`
- `cmdSalt`
- `cmdSigR8[2]`
- `cmdSigS`
- `currentStateRoot`
- `activeStateRoot`
- current `stateLeaf[10]`
- state-leaf Merkle path with two quinary levels
- active-state leaf and Merkle path with two quinary levels
- current vote weight and one-level vote-option path
- `isValid`
- command-derived values:
  `cmdStateIndex`, `cmdVoteOptionIndex`, `cmdNewVoteWeight`, `cmdNonce`,
  `cmdPollId`, `cmdNewPubKey[2]`, `newBalance`, `newSlNonce`

Compatibility flags:

- `isSignatureValid` stands in for the Circom `VerifySignature()` output in
  the smaller ECDH-only executables. The signature-enabled executables derive
  it from the BabyJubJub verifier.
- `isDecryptionActive` is still an explicit `ProcessOne` field for
  compatibility, but the batch state-transition executable constrains it with
  a BabyJubJub scalar-multiplication transcript for
  `ElGamalDecrypt(stateLeaf.c1, stateLeaf.c2, coordPrivKey)`.

Encrypted message binding:

The current slice now constrains the supplied encrypted `msg[10]` to the
supplied `decryptedCommand[7]` with the same stream shape as AMACI
`PoseidonDecryptWithoutCheck(7)`.

```text
state0 = PoseidonPermT4([
  0,
  sharedKey[0],
  sharedKey[1],
  7 * 2^128
])

decrypted[0] = msg[0] - state0[1] mod BN254
decrypted[1] = msg[1] - state0[2] mod BN254
decrypted[2] = msg[2] - state0[3] mod BN254

state1 = PoseidonPermT4([state0[0], msg[0], msg[1], msg[2]])

decrypted[3] = msg[3] - state1[1] mod BN254
decrypted[4] = msg[4] - state1[2] mod BN254
decrypted[5] = msg[5] - state1[3] mod BN254

state2 = PoseidonPermT4([state1[0], msg[3], msg[4], msg[5]])

decrypted[6] = msg[6] - state2[1] mod BN254
```

`PoseidonDecryptWithoutCheck(7)` pads internally to three 3-field blocks, so
`msg[7]`, `msg[8]`, and `msg[9]` are not command fields in this slice. The
stateful `ProcessMessages` executable separately enforces that each
`ProcessOne` witness uses the exact boundary message from the public message
hash chain. The lighter `process_messages_stateful` path still accepts
`sharedKey[2]` as witness input; the `process_messages_stateful_with_ecdh` path
derives and binds those shared keys with ECDH transcripts.

## Standalone ECDH Slice

The migration now includes a standalone Cairo executable for the AMACI ECDH
relation:

```text
sharedKey[2] = EscalarMulAny(253)(encPubKey[2], coordPrivKey)
```

The executable receives a 253-step scalar multiplication transcript. For each
bit it verifies:

- the bit is boolean
- `sum = accumulator + exponent`
- `nextExp = exponent + exponent`
- `nextAccumulator = bit ? sum : accumulator`
- the scalar reconstructed from all bits equals the supplied private key
- the final accumulator equals the expected `sharedKey[2]`

Each BabyJubJub addition is checked with the same cross-multiplied Edwards
equations as Circom's `BabyAdd`, so Cairo does not need modular division or
inversion inside the program.

The migration also includes `process_one_with_ecdh`, a single-message
composition executable:

```text
verify ECDH transcript
assert transcript.expected == processOne.sharedKey
verify PoseidonDecryptWithoutCheck(7)
verify ProcessOne state transition
```

## Split Proof Path

For dense batches, the migration now also exposes
`process_message_step_with_ecdh_signature`. This executable proves one message
slot with public output containing:

- `messageIndex`
- `packedVals`
- `coordPubKeyHash`
- `previousMessageHash`
- `nextMessageHash`
- `currentStateRoot`
- `newStateRoot`
- `currentStateCommitment`
- `newStateCommitment`
- `activeStateRoot`
- `expectedPollId`

The relation checks:

- `packedVals` matches `isQuadraticCost`, `numSignUps`, and `maxVoteOptions`.
- `coordPrivKey` derives the boundary `coordPubKey`, and
  `coordPubKeyHash == Poseidon(coordPubKey[0], coordPubKey[1])`.
- The supplied `msg[10]` and `encPubKey[2]` advance
  `previousMessageHash -> nextMessageHash` with the same empty-message rule as
  the batch boundary.
- The ECDH transcript derives `ProcessOne.sharedKey` from the same
  `coordPrivKey` and `encPubKey`.
- The BabyJubJub Poseidon signature witness derives `isSignatureValid`.
- The active-state ElGamal decrypt transcript derives `isDecryptionActive`.
- The `ProcessOne` state transition maps
  `currentStateRoot -> newStateRoot`.
- Step `4` proves `currentStateCommitment` opens to `currentStateRoot` with
  the boundary `currentStateSalt`; step `0` proves `newStateCommitment` opens
  to `newStateRoot` with the boundary `newStateSalt`.

The intended proof composition is:

```text
1 boundary proof
5 process-message-step proofs
```

A wrapper or off-chain checker must chain the public outputs:

```text
boundary.batchStartHash == step0.previousMessageHash
step0.nextMessageHash == step1.previousMessageHash
...
step4.nextMessageHash == boundary.batchEndHash

boundary.currentStateCommitment == step4.currentStateCommitment
boundary.newStateCommitment == step0.newStateCommitment

step4.newStateRoot == step3.currentStateRoot
...
step1.newStateRoot == step0.currentStateRoot
```

The final state endpoint is enforced by comparing `step0.newStateCommitment`
to the boundary output and relying on the step `0` commitment-opening proof.

The split path lowers peak prover memory by proving one message slot at a time,
but the Starknet wrapper that verifies all six facts and enforces this chaining
is still pending.

The migration also includes `process_messages_stateful_with_ecdh`, a
five-message composition executable:

```text
verify public ProcessMessages boundary
for each non-empty message i:
  assert ecdh_i.scalar == coordPrivKey
  assert ecdh_i.base == boundary.encPubKey_i
  assert ecdh_i.expected == processOne_i.sharedKey
verify PoseidonDecryptWithoutCheck(7) for each ProcessOne
verify reverse-order ProcessMessages state transition
return canonical public output
```

Empty message slots still only require an invalid `ProcessOne` transition and
skip ECDH verification.

Packed command checks:

`decryptedCommand` mirrors the seven command elements emitted by
`PoseidonDecryptWithoutCheck(7)`, and `packedCommand` mirrors the Circom
`packedCommandOut` from `MessageToCommand`:

```text
decryptedCommand[0] = packed command data
decryptedCommand[1] = new public key x
decryptedCommand[2] = new public key y
decryptedCommand[3] = salt
decryptedCommand[4] = sig R8 x
decryptedCommand[5] = sig R8 y
decryptedCommand[6] = sig S

packedCommand[0] = decrypted[0]   // packed command data
packedCommand[1] = decrypted[1]   // new public key x
packedCommand[2] = decrypted[2]   // new public key y
```

The executable first enforces:

```text
packedCommand[0] == decryptedCommand[0]
packedCommand[1] == decryptedCommand[1]
packedCommand[2] == decryptedCommand[2]
cmdSalt          == decryptedCommand[3]
cmdSigR8[0]      == decryptedCommand[4]
cmdSigR8[1]      == decryptedCommand[5]
cmdSigS          == decryptedCommand[6]
```

The current Cairo slice unpacks `packedCommand[0]` with the same 7 x 32-bit
layout used by `UnpackElement(7)`:

```text
out[0] = bits 192..223 = pollId
out[1] = bits 160..191 = voteWeight high32
out[2] = bits 128..159 = voteWeight mid32
out[3] = bits 96..127  = voteWeight low32
out[4] = bits 64..95   = voteOptionIndex
out[5] = bits 32..63   = stateIndex
out[6] = bits 0..31    = nonce
```

It then enforces:

```text
cmdPollId          == out[0]
cmdNewVoteWeight   == out[3] + out[2] * 2^32
                    + out[1] * 18446744073709552000
cmdVoteOptionIndex == out[4]
cmdStateIndex      == out[5]
cmdNonce           == out[6]
cmdNewPubKey[0]    == packedCommand[1]
cmdNewPubKey[1]    == packedCommand[2]
```

The high-factor constant intentionally follows the current AMACI Circom
`Uint32to96()` implementation. This keeps the migration tied to the code that
exists today, even though the decimal constant differs from exact `2^64`.

Validator checks:

```text
validStateIndex      = cmdStateIndex <= numSignUps && cmdStateIndex <= 24
validVoteOptionIndex = cmdVoteOptionIndex < maxVoteOptions
validNonce           = cmdNonce == stateLeaf[4] + 1
validPollId          = cmdPollId == expectedPollId
validVoteWeight      = cmdNewVoteWeight <= 147946756881789319005730692170996259609

currentCost = isQuadraticCost ? currentVoteWeight^2 : currentVoteWeight
newCost     = isQuadraticCost ? cmdNewVoteWeight^2 : cmdNewVoteWeight
newBalance  = stateLeaf[2] + currentCost - newCost

messageValid =
  isSignatureValid &&
  validStateIndex &&
  validVoteOptionIndex &&
  validNonce &&
  validPollId &&
  validVoteWeight &&
  stateLeaf[2] + currentCost >= newCost

isValid =
  messageValid &&
  isDecryptionActive &&
  activeStateLeaf == 0
```

Selectors:

```text
stateIndex = isValid ? cmdStateIndex : 24
voteOptionIndex = isValid ? cmdVoteOptionIndex : 0
updatedVoteWeight = isValid ? cmdNewVoteWeight : currentVoteWeight
```

The executable enforces:

- `decryptedCommand` maps to `packedCommand`, salt, and signature witness
  fields.
- `packedCommand` unpacks to the supplied command-derived fields.
- `isValid` matches the validator result above.
- For valid commands, `newBalance` and `newSlNonce` match the computed balance
  and command nonce.
- `Hasher10(stateLeaf)` is included in `currentStateRoot` at `stateIndex`.
- `activeStateLeaf` is included in `activeStateRoot` at `stateIndex`.
- `currentVoteWeight` is included in the state leaf's vote root at
  `voteOptionIndex`. A zero vote root is interpreted as the one-level quinary
  zero root.
- `updatedVoteWeight` produces `newVoteOptionRoot` over the same vote path.
- The new state leaf updates pubkey, balance, vote root, and nonce only when
  `isValid == 1`; fixed state fields are preserved and the last field is reset
  to zero.
- The executable returns the derived `newStateRoot` as a `u256`.

The signature-enabled single-message executables bind this deterministic slice
to ECDH/shared-key derivation and BabyJubJub signature verification.

## Five-Message State Transition

The current migration also adds a batch-level state transition for
`ProcessMessages(2, 1, 5)`.

Inputs:

- batch `currentStateRoot`
- batch `activeStateRoot`
- expected batch `newStateRoot`
- five `ProcessOne` state-transition witnesses

AMACI Circom processes the batch in reverse message order. The executable
therefore enforces:

- witness `4` starts at the batch `currentStateRoot`
- witness `3` starts at witness `4`'s output root
- witness `2` starts at witness `3`'s output root
- witness `1` starts at witness `2`'s output root
- witness `0` starts at witness `1`'s output root
- every witness uses the same batch `activeStateRoot`
- every witness uses the same batch `coordPrivKey`
- every witness's `isDecryptionActive` equals
  `1 - odd(ElGamalDecrypt(stateLeaf.c1, stateLeaf.c2, coordPrivKey).x)`
- witness `0` outputs the expected batch `newStateRoot`

This composes the migrated Merkle-state portion of `ProcessMessages`; the
stateful ECDH and ECDH+signature executables then bind it to encrypted message
decryption and signature validation.

## Stateful ProcessMessages Boundary

The `process_messages_stateful` executable combines the public boundary and
five-message state transition:

- verifies the same packed values, commitments, message hash chain, SHA-256
  `inputHash`, and canonical public output as `process_messages_boundary`
- verifies the five-message state-root chain from `currentStateRoot` to
  `newStateRoot`
- enforces that the state transition starts from the same `currentStateRoot`
  and `activeStateRoot` used by the public boundary
- enforces that each `ProcessOne` witness uses the same `isQuadraticCost`,
  `numSignUps`, `maxVoteOptions`, and `expectedPollId` as the public boundary
- enforces that each `ProcessOne` witness uses the exact message committed by
  the public boundary's message hash chain
- enforces that the state transition's final root equals the `newStateRoot`
  committed by `newStateCommitment`
- enforces that an empty message slot, identified by `encPubKey[0] == 0`,
  cannot drive a valid `ProcessOne` transition
- the ECDH stateful executables additionally enforce that the private
  coordinator key derives the boundary coordinator public key via BabyJubJub
  `Base8`

The ECDH-only stateful executable still supplies signature validity as a
witness value for smaller compatibility checks. The
`process_messages_stateful_with_ecdh_signature` executable derives it from the
BabyJubJub verifier for all five `ProcessOne` witnesses.

## Canonical Public Output

The Cairo public output should use a fixed felt list:

```text
[
  magic,
  version,
  circuit_id,
  state_tree_depth,
  vote_option_tree_depth,
  message_batch_size,
  packed_vals_low128,
  packed_vals_high128,
  coord_pub_key_hash_low128,
  coord_pub_key_hash_high128,
  batch_start_hash_low128,
  batch_start_hash_high128,
  batch_end_hash_low128,
  batch_end_hash_high128,
  current_state_commitment_low128,
  current_state_commitment_high128,
  new_state_commitment_low128,
  new_state_commitment_high128,
  deactivate_commitment_low128,
  deactivate_commitment_high128,
  expected_poll_id_low128,
  expected_poll_id_high128,
  input_hash_low128,
  input_hash_high128
]
```

Constants:

```text
magic = 0x4d414349535441524b      // "MACISTARK"
version = 1
circuit_id = 0x414d4143495f50524f434553535f4d45535341474553
           // "AMACI_PROCESS_MESSAGES"
```
