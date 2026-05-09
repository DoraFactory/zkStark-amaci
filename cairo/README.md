# Cairo target

This folder is the first Cairo target for the AMACI STARK migration. It is kept
separate from the existing Circom circuits.

This target is now a Scarb executable. The local toolchain can compile it and
execute it with generated AMACI fixture arguments. Full local proving is
currently blocked by this macOS/arm64 machine's resources.

## Current migration scope

The Cairo program now mirrors the fixed-size AMACI `TallyVotes(2, 1, 1)` dataflow:

- `packedVals = (numSignUps << 32) + batchNum`
- `batchNum * 5 <= numSignUps`
- first-batch handling for `currentTallyCommitment`
- vote-option root selection against each state leaf's vote root field
- per-option tally update:
  `current + sum(vote * (vote + 10^24))`
- canonical public output generation
- AMACI `Hasher10` state leaf hashing:
  `HashLeftRight(Hasher5(first 5 fields), Hasher5(last 5 fields))`
- Circom-compatible BN254 Poseidon T3/T6 hashing for `HashLeftRight`,
  `Hasher5`, quinary roots, vote roots, and tally commitments
- Circom-compatible SHA-256 `inputHash` over four `uint256` values, reduced
  modulo the BN254 scalar field

The `process_messages_boundary` executable is the first
`ProcessMessages(2, 1, 5)` migration step. It verifies:

- `packedVals = (isQuadraticCost << 64) + (numSignUps << 32) + maxVoteOptions`
- `coordPubKeyHash = Poseidon(coordPubKey[0], coordPubKey[1])`
- `inputHash = sha256(packedVals, coordPubKeyHash, batchStartHash,
  batchEndHash, currentStateCommitment, newStateCommitment,
  deactivateCommitment, expectedPollId) mod BN254`
- the AMACI message hash chain from `batchStartHash` to `batchEndHash`
  using 10-element encrypted messages and `Hasher13`
- current state, new state, and deactivate commitments

The `process_one_state_transition` executable is the first `ProcessOne`
migration slice. It verifies:

- `msg[10]` decrypts into `decrypted_command[0..6]` with the Circom-compatible
  `PoseidonDecryptWithoutCheck(7)` stream cipher and a witness `shared_key[2]`
- `decrypted_command[0..6]` maps to packed command data, new public key, salt,
  and signature witness fields as in AMACI `MessageToCommand`
- `packed_command[0]` unpacks to poll id, nonce, state index, vote option
  index, and vote weight using the current AMACI `MessageToCommand` layout
- `packed_command[1..2]` match the command new public key fields
- deterministic `MessageValidator` checks for state index, vote option index,
  nonce, poll id, vote-weight bound, linear/quadratic cost, and voice-credit
  sufficiency
- the final `StateLeafTransformer` validity selector, with signature binding
  available in the signature executables and active-state ElGamal decrypt
  parity bound in the five-message state-transition witness
- current state-leaf inclusion in `currentStateRoot`
- active-state leaf inclusion in `activeStateRoot`
- current vote-weight inclusion in the state leaf's vote root
- valid/invalid message selectors for state index and vote-option index
- vote-option root update and resulting new state-root derivation

The `ecdh_shared_key` executable is the first standalone BabyJubJub ECDH
migration slice. It verifies a 253-step scalar multiplication transcript for:

```text
shared_key = priv_key * pub_key
```

The transcript avoids in-program modular inversion by checking each BabyJubJub
addition with the same cross-multiplied equations used by Circom constraints.
The `process_one_with_ecdh` executable wires that ECDH slice into one
`ProcessOne` witness: the verified ECDH output must equal `shared_key[2]`,
then the existing `ProcessOne` path uses it for `PoseidonDecryptWithoutCheck(7)`
and state-root transition verification.

The `process_messages_stateful_with_ecdh` executable wires the same ECDH
binding into the fixed five-message batch. For every non-empty boundary
`encPubKey[2]`, it enforces:

- the ECDH transcript scalar equals the shared `coord_priv_key`
- the ECDH transcript base equals that boundary `encPubKey[2]`
- the ECDH transcript output equals the corresponding `ProcessOne.shared_key`

It also enforces the coordinator key binding:

```text
coord_pub_key = coord_priv_key * BabyJubJub.Base8
```

The `process_messages_state_transition` executable chains five
`ProcessOneStateTransitionWitness` values and enforces:

- AMACI's reverse processing order: witness `4` starts at the batch
  `currentStateRoot`, then witnesses `3`, `2`, `1`, and `0`
- every witness uses the same `activeStateRoot`
- witness `0` outputs the batch `newStateRoot`

The `process_messages_stateful` executable combines the public boundary with
the five-message state transition. It returns the canonical public output only
after the message hash chain, commitments, final state root, and canonical
`inputHash` all agree. Empty message slots, identified by `encPubKey[0] == 0`,
are also forced to use an invalid `ProcessOne` transition. The stateful
executable also requires every `ProcessOne` witness to use the boundary's
message, `isQuadraticCost`, `numSignUps`, `maxVoteOptions`, and
`expectedPollId`.

The `verify_signature` executable migrates the standalone AMACI
`VerifySignature` primitive. It computes `M = Poseidon(packedCommand[0..2])`
and checks the EdDSA-Poseidon relation
`S * Base8 == R8 + Poseidon(R8, A, M) * (8 * A)`, returning `1` or `0`.

`process_one_with_signature` and `process_one_with_ecdh_signature` wire that
signature result into one `ProcessOne` witness.
`process_messages_stateful_with_ecdh_signature` carries the same check through
the fixed five-message stateful batch. The ECDH-only executable remains useful
for smaller compatibility checks.

The `add_new_key` executable migrates the fixed
`AddNewKey(stateTreeDepth=2)` relation. It verifies:

- `nullifier = Poseidon(oldPrivateKey, pollId)`
- `sharedKey = oldPrivateKey * coordPubKey`
- `deactivateLeaf = Hasher5(c1[0], c1[1], c2[0], c2[1], Poseidon(sharedKey))`
- depth-4 deactivate tree inclusion for `deactivateLeaf`
- ElGamal re-randomization:
  `d1 = c1 + randomVal * Base8` and `d2 = c2 + randomVal * coordPubKey`
- `inputHash = Sha256Hasher(9)` over the AMACI AddNewKey public values
- canonical AddNewKey public output

The first `ProcessDeactivateMessages(2, 5)` slices are also present:

- `process_deactivate_messages_boundary` verifies the public-input boundary:
  `coordPubKeyHash`, `currentDeactivateCommitment`, `Sha256Hasher(8)`, the
  canonical public output, and the deactivate message hash chain. This chain
  follows the AMACI Circom rule that an empty deactivate message is detected
  by `msg[0] == 0`.
- `process_deactivate_one` verifies one `ProcessOne` transition: signature
  verification over `packedCmd[0..2]`, ElGamal decrypt parity for the existing
  active-state ciphertext and the submitted deactivate ciphertext,
  state-root inclusion, active-state root update, depth-4 deactivate-tree
  insertion, ECDH-derived deactivate leaf, and non-zero `newActiveState`.
- `process_deactivate_messages_state_transition` chains five
  `ProcessDeactivate` `ProcessOne` witnesses in AMACI's forward batch order.
  It enforces the active/deactivate root chain, common `coordPrivKey`,
  common `currentStateRoot`, common `expectedPollId`, and
  `deactivateIndex = deactivateIndex0 + i`.
- `process_deactivate_messages_stateful` combines the public boundary with the
  five-message state transition, enforces
  `coordPubKey = coordPrivKey * BabyJubJub.Base8`, verifies the final
  `newDeactivateRoot`, recomputes `newDeactivateCommitment`, binds each
  non-empty boundary encrypted message and `encPubKey` to the corresponding
  `ProcessOne` command fields through ECDH and
  `PoseidonDecryptWithoutCheck(7)`, and returns the canonical public output.

`TallyVotes` still receives explicit `Hash2Claim`, `Hash5Claim`,
`Hash10Claim`, and `Sha256U256x4Claim` values in the generated input, but
those values are compatibility assertions. Cairo recomputes the hashes
internally and rejects the witness if any claimed output differs.

Use the hash-vector exporter to produce focused test inputs for those
implementations and cross-checks:

```sh
npm --prefix .. run export:hash-vectors -- --out /tmp/zkstark-amaci-hash-vectors.json
npm --prefix .. run verify:hash-vectors
```

Current local commands:

```sh
npm --prefix .. run prepare:cairo-args
scarb execute \
  --executable-name tally_votes \
  --arguments-file /tmp/zkstark-amaci-cairo-args.json \
  --print-program-output
node ../tools/prepare-ecdh-input.mjs \
  <ecdh-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-ecdh-args.json
scarb execute \
  --executable-name ecdh_shared_key \
  --arguments-file /tmp/zkstark-amaci-ecdh-args.json \
  --print-program-output
node ../tools/prepare-process-one-with-ecdh-input.mjs \
  <process-one-input.json> \
  <ecdh-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-process-one-with-ecdh-args.json
scarb execute \
  --executable-name process_one_with_ecdh \
  --arguments-file /tmp/zkstark-amaci-process-one-with-ecdh-args.json \
  --print-program-output
node ../tools/prepare-process-one-input.mjs \
  <process-one-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-process-one-args.json
scarb execute \
  --executable-name process_one_state_transition \
  --arguments-file /tmp/zkstark-amaci-process-one-args.json \
  --print-program-output
node ../tools/prepare-process-messages-state-input.mjs \
  <process-messages-state-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-process-messages-state-args.json
scarb execute \
  --executable-name process_messages_state_transition \
  --arguments-file /tmp/zkstark-amaci-process-messages-state-args.json \
  --print-program-output
node ../tools/prepare-process-messages-stateful-input.mjs \
  <process-messages-stateful-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-process-messages-stateful-args.json
scarb execute \
  --executable-name process_messages_stateful \
  --arguments-file /tmp/zkstark-amaci-process-messages-stateful-args.json \
  --print-program-output
node ../tools/prepare-process-messages-stateful-with-ecdh-input.mjs \
  <process-messages-stateful-ecdh-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-process-messages-stateful-ecdh-args.json
scarb execute \
  --executable-name process_messages_stateful_with_ecdh \
  --arguments-file /tmp/zkstark-amaci-process-messages-stateful-ecdh-args.json \
  --print-program-output
npm --prefix .. run prove:tally
```

`tools/run-cairo-proof.sh` performs the full local flow:

1. prepare `scarb execute` arguments from an existing tally input JSON,
2. run `scarb prove --execute`,
3. run `scarb verify` against the generated proof.

For the current AMACI fixture, step 1 succeeds and produces the canonical
output, but step 2 is killed locally with exit code `137` / `Killed: 9`.

The latest local resource measurement for
`../fixtures/tally-small/000000.json`
is:

- execution steps: `19,514,414`
- max memory address: `27,947,371`
- memory holes: `5,287,008`
- range-check builtin uses: `5,139,640`
- bitwise builtin uses: `2,880`
- output builtin uses: `16`

This is not yet the Integrity submission path. Integrity/Stone serialization
still needs a dedicated integration step once the expected proof format and
FactRegistry interface are pinned.
