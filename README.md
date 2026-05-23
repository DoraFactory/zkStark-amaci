# zkStark-amaci

Starknet/Cairo implementation of a zkSTARK-backed AMACI round.

The repository contains two layers:

- **Cairo programs** under `cairo/`: deterministic AMACI proof programs that
  compute and expose canonical public outputs.
- **Starknet contracts** under `contracts/`: wrapper contracts that consume
  registered proof facts and advance AMACI round state on Starknet.

The current tested round is fixed to the small AMACI parameter set used by the
E2E fixtures:

| Parameter | Value |
| --- | ---: |
| `stateTreeDepth` | `2` |
| `intStateTreeDepth` | `1` |
| `voteOptionTreeDepth` | `1` |
| `messageBatchSize` | `3` |

## Protocol Shape

AMACI is represented on Starknet as a sequence of state commitments. Expensive
private computation is proven by Cairo programs, while the Starknet round
contract only verifies registered facts and public-output links.

```text
round deploy
  -> add new key proof fact
  -> process messages proof facts
  -> tally proof fact
  -> final tally commitment stored on Starknet
```

For the current E2E path, the Starknet round consumes three facts:

```text
add-new-key-native
process-messages-stage-native   // messages[0..2]
tally-native
```

The process-message stage fact is linked by state commitments:

```text
stage.current_state == round.state_commitment
stage.new_state     == final processed state
```

This gives a compact tested flow:

```text
add-key x1 + processMessage stage x1 + tally x1 = 3 facts
```

## Cairo Programs

The Cairo package is in `cairo/`. Its executable targets are declared in
`cairo/Scarb.toml`.

### Add Key

`add_new_key_native` proves that a new key operation is well formed. The public
output binds:

- the key/nullifier data,
- the current round context,
- the canonical AMACI public-output hash used by the wrapper.

The Starknet wrapper uses this fact to count the key as accepted and reject
duplicate nullifier usage.

### Process Messages

Process-message proving is available at two levels.

The **current E2E round path** uses the stage program:

| Program | Role |
| --- | --- |
| `process_messages_stage_native` | Proves the full 3-message batch in one Cairo program. |

The lower-level component programs are also present for debugging, cost
measurement, and future aggregation work:

| Program | Role |
| --- | --- |
| `process_messages_native_boundary` | Batch-level start/end commitment constraints. |
| `process_message_coord_key_native` | Coordinator public/private key binding for the batch. |
| `process_message_ecdh_native` | One message ECDH/shared-key binding. |
| `process_message_decrypt_native` | One message decrypt binding. |
| `process_message_signature_native` | One command authorization/signature binding. |
| `process_message_step_core_native` | One message state transition and commitment update. |

For `messageBatchSize = 3`, the fully expanded component proof distribution is:

```text
1 coord-key
3 ecdh
3 decrypt
3 signature
3 step-core
1 boundary
```

### Process Deactivate

The deactivate path mirrors the message-processing model and is implemented for
separate deactivate flows:

| Program | Role |
| --- | --- |
| `process_deactivate_native_boundary` | Deactivate batch boundary constraints. |
| `process_deactivate_coord_key_native` | Coordinator key binding. |
| `process_deactivate_ecdh_native` | Command/deactivate-leaf ECDH binding. |
| `process_deactivate_signature_native` | Deactivate command authorization binding. |
| `process_deactivate_decrypt_native` | Current/new decrypt parity binding. |
| `process_deactivate_step_core_native` | Deactivate state transition and root update. |

The minimal voting/tallying E2E round does not include a deactivate operation,
but the Cairo programs and wrapper path are implemented and tested.

### Tally

`tally_votes_native` proves the final tally computation from the processed AMACI
state. Its public output binds:

- the current state commitment,
- the new tally commitment,
- the native tally input hash,
- the AMACI circuit identifier.

The Starknet round stores the tally commitment after the fact is verified.

## Public Outputs And Facts

Every Cairo program emits a canonical `Array<felt252>` public output. The
wrapper contracts do not replay private computation. Instead they check:

```text
program hash is allowed
public output has the expected AMACI circuit id
public output links to the current round state
fact hash is registered in Integrity / FactRegistry
verification hash or security bits satisfy the configured policy
```

The fact path used by the current Starknet tests is:

```text
Cairo program + Cairo1 input
  -> Atlantic / Stone proof
  -> Integrity proof verification on Starknet
  -> registered fact hash
  -> AMACI wrapper consumes fact and updates round state
```

## Starknet Contracts

The Starknet package is in `contracts/`.

| Contract | Role |
| --- | --- |
| `AddNewKeyStarkWrapper` | Verifies add-key public output and registered fact. |
| `ProcessMessagesStarkWrapper` | Verifies process-message public output and registered fact. |
| `ProcessDeactivateStarkWrapper` | Verifies deactivate public output and registered fact. |
| `TallyVotesStarkWrapper` | Verifies tally public output and registered fact. |
| `MockAmaciRound` | Round-level prototype that wires all AMACI facts together and tracks round state. |
| `MockIntegrity` | Local/devnet test substitute for the Integrity fact registry interface. |

`MockAmaciRound` is the current E2E round contract. It maintains:

```text
stateCommitment
deactivateCommitment
tallyCommitment
keysAdded
messageBatchesProcessed
deactivateBatchesProcessed
totalFactsAccepted
tallySubmitted
```

The round contract accepts Atlantic metadata facts through wrapper entrypoints
for add-key, process-messages, process-deactivate, and tally. Each entrypoint
reconstructs the expected public-output hash, verifies the fact against the
configured Integrity registry mode, checks state continuity, then updates the
round commitment.

## Current Starknet E2E Flow

The current Sepolia-tested flow is:

```text
deploy MockAmaciRound
  -> submit add-new-key-native fact
  -> submit process-messages-stage-native fact
  -> submit tally-native fact
```

Business data for the tested small round:

- one round,
- one key-add operation,
- one message batch with three vote messages,
- final tally stored on-chain as a commitment.

The chain stores commitments and fact consumption state. Plaintext vote totals
remain local fixture data; correctness is established by the tally proof and
the on-chain commitment check.

Measured Sepolia costs for the previous 4-fact path are retained in
`e2e-round.md`. After the `2-1-1-3` switch, the current target path has one
process-message stage fact instead of the old two segment facts.

Previous measured Sepolia costs:

| Scope | Cost |
| --- | ---: |
| Atlantic / Integrity proof verification | `17.050048590 STRK` |
| AMACI wrapper business calls | `0.249605962 STRK` |
| Total, excluding round deploy | `17.299654552 STRK` |
| Total, including round deploy | `17.361780361 STRK` |

Earlier full component measurement data and transaction links are kept in
`e2e-round.md`.

## Repository Layout

```text
cairo/       Cairo proof programs and Scarb executable targets.
contracts/   Starknet wrappers, mock round state, and test Integrity registry.
src/         JavaScript evaluators, public-output encoders, and Atlantic helpers.
tools/       Fixture generation, Cairo execution, Stone, and Atlantic scripts.
tests/       JavaScript model and pipeline tests.
fixtures/    Small AMACI fixture inputs.
docs/        Operational runbooks.
```

Important files:

| File | Purpose |
| --- | --- |
| `cairo/Scarb.toml` | Cairo executable target list. |
| `cairo/src/native_add_new_key.cairo` | Add-key proof program. |
| `cairo/src/native_process_messages_stage.cairo` | Process-message stage proof program. |
| `cairo/src/native_process_message_components.cairo` | Process-message component proof programs. |
| `cairo/src/native_tally_votes.cairo` | Tally proof program. |
| `contracts/src/mock_amaci_round.cairo` | Round-level Starknet wrapper used in E2E tests. |
| `contracts/src/*_wrapper.cairo` | Per-operation Starknet fact wrappers. |
| `src/public-output.mjs` | Canonical public-output encoding. |
| `src/atlantic/query-bundle.mjs` | Atlantic-compatible `programFile` / `inputFile` export. |
| `src/atlantic/mock-round-call.mjs` | Wrapper call construction from Atlantic results. |
| `e2e-round.md` | Full Sepolia E2E run notes, costs, tx hashes, and local artifact paths. |

## Quick Start

Install JavaScript dependencies:

```sh
npm ci
```

Run the main validation suite:

```sh
npm test
npm run test:contracts
```

Current expected contract baseline:

```text
npm run test:contracts 38 passed, 0 failed
```

Build and test the Cairo programs directly:

```sh
cd cairo
scarb build
scarb test
```

## Generate Round Inputs

Generate the small coherent AMACI round fixture:

```sh
npm run write:full-round-fixture -- \
  --out-dir target/full-native-round-fixture \
  --text
```

The output includes:

```text
add-new-key-native.json
process-messages-boundary-native.json
tally-native.json
chain.json
```

Prepare one Cairo input:

```sh
npm run prepare:circuit -- \
  --circuit tally-native \
  fixtures/tally-small/000000.json \
  --out target/tally-native-prepared.json \
  --cairo-args-out target/tally-native-args.json
```

Indexed process-message and process-deactivate components use `--message-index 0..2`:

```sh
npm run prepare:process-message-step-core-native -- \
  --message-index 0 \
  --out target/process-message-step-core-0.json
```

## Local Cairo Proofs

Run local Scarb/Stwo proof validation for the small native split path:

```sh
OUT_DIR=/absolute/path/to/zkstark-amaci-proofs

npm run prove:all-native-split-small -- \
  --tally-input fixtures/tally-small/000000.json \
  --out-dir "$OUT_DIR/all-native-split"
```

Run one proof:

```sh
npm run prove:tally-native -- --out-dir "$OUT_DIR/tally-native"
npm run prove:add-new-key-native -- --out-dir "$OUT_DIR/add-new-key-native"
npm run prove:process-message-step-core-native -- \
  --message-index 0 \
  --out-dir "$OUT_DIR/process-message-step-core-native-0"
```

The local Scarb/Stwo path is useful for development. Current Starknet
application-layer verification uses the Stone/Atlantic path.

## Stone / Atlantic Path

Check local Stone tooling:

```sh
npm run check:stone-toolchain
```

Generate a Stone AIR run for a Cairo program:

```sh
CAIRO_CORELIB_DIR=~/cairo-vm/cairo1-run/corelib \
npm run stone:air:circuit -- \
  --circuit tally-native \
  --input fixtures/tally-small/000000.json \
  --out-dir target/stone/tally-native/stone-air
```

Export an Atlantic-compatible multipart bundle:

```sh
npm run export:atlantic-query -- \
  --stone-air-run target/stone/tally-native/stone-air/stone-air-run.json \
  --out-dir target/atlantic/tally-native \
  --network TESTNET \
  --text
```

The bundle contains:

```text
programFile                  Cairo1 Sierra JSON
inputFile                    Cairo1 Rust VM input
submit-atlantic-query.sh     curl command for Atlantic
atlantic-query-bundle.json   manifest
```

Submit with an Atlantic API key:

```sh
ATLANTIC_API_KEY=... target/atlantic/tally-native/submit-atlantic-query.sh
```

Fetch query status and artifacts:

```sh
npm run atlantic:fetch-query -- \
  --query-id <atlantic-query-id> \
  --out-dir target/atlantic-query-check \
  --download-artifacts \
  --text
```

Export a Starknet wrapper call after the Atlantic query reaches `DONE`:

```sh
npm run export:atlantic-round-call -- \
  --query-result target/atlantic-query-check/atlantic-query-result.json \
  --metadata target/atlantic-query-check/artifacts/metadata.json \
  --wrapper-address <MockAmaciRound-address> \
  --profile <sncast-profile> \
  --out target/atlantic-round-call.json \
  --text
```

## Development Notes

- The current E2E round uses 4 facts because the single 5-message
  `process_messages_stage_native` proof exceeds the current Starknet L2
  Integrity split-calldata limit.
- The component-level process-message and process-deactivate programs remain
  useful for detailed proof composition, cost measurement, and future recursive
  aggregation work.
- `MockAmaciRound` is a round-state prototype for validation and cost
  measurement. A production AMACI contract should pin the final Integrity
  interface, account model, operator flow, and round lifecycle policy.
