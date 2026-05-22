# zkStark-amaci

Starknet-native STARK proof-layer prototype for AMACI.

This repository is intentionally independent from the existing Circom,
CosmWasm, SDK, and operator code. The current implementation is a small,
fixed-parameter AMACI migration used to prove and measure a Starknet-friendly
round flow:

- `stateTreeDepth = 2`
- `intStateTreeDepth = 1`
- `voteOptionTreeDepth = 1`
- `messageBatchSize = 5`

The proof-facing path is now **native AMACI**: public commitments, input
hashes, fact bindings, and wrapper checks use Starknet-friendly `felt252`
values and Starknet Poseidon. The older BN254 Poseidon/SHA-256 compatibility
executables are still present for reference and regression tests, but they are
not the default path for Starknet verification.

## Current Status

- Native Cairo circuits exist for add-key, process-messages, process-deactivate,
  and tally.
- The native process flows are split into smaller component proofs so the
  expensive ECDH/signature/decrypt work can be verified as separate facts.
- Stone AIR generation supports every native circuit used by the current small
  round.
- Atlantic/Herodotus submission uses the official-compatible shape:
  Cairo1 `programFile`, Cairo1 Rust VM `inputFile`, and proving/verification
  parameters. Do not upload local `stone-proof.json` or Integrity split calldata
  for this path.
- Starknet wrapper contracts exist for add-key, process-messages,
  process-deactivate, tally, and the aggregate `MockAmaciRound` round-state
  prototype.
- The full component E2E round has been exercised on Sepolia with Atlantic
  registered facts and wrapper-side fact consumption.

The current prototype is for migration validation and cost measurement. It is
not yet the final production AMACI round contract or SDK/operator integration.

## Native Circuit Families

The active native circuit set is:

| Flow | Native circuits |
| --- | --- |
| Add key | `add-new-key-native` |
| Process messages boundary | `process-messages-boundary-native` |
| Process messages components | `process-message-coord-key-native`, `process-message-ecdh-native`, `process-message-decrypt-native`, `process-message-signature-native`, `process-message-step-core-native` |
| Process deactivate boundary | `process-deactivate-boundary-native` |
| Process deactivate components | `process-deactivate-coord-key-native`, `process-deactivate-ecdh-command-native`, `process-deactivate-ecdh-leaf-native`, `process-deactivate-signature-native`, `process-deactivate-decrypt-current-native`, `process-deactivate-decrypt-new-native`, `process-deactivate-step-core-native` |
| Tally | `tally-native` |

For `messageBatchSize = 5`, the full process-messages component set is:

```text
1 boundary
1 coordinator-key proof
5 ECDH proofs
5 decrypt proofs
5 signature proofs
5 step-core proofs
```

The process-deactivate component set is similar but includes both command ECDH
and deactivate-leaf ECDH plus current/new decrypt parity proofs.

## Repository Layout

```text
cairo/       Cairo native and legacy compatibility executables.
contracts/   Starknet wrappers, mock Integrity registry, and mock round state.
src/         JavaScript evaluators, public output encoders, Atlantic helpers.
tools/       Fixture generation, proof orchestration, Stone/Atlantic scripts.
tests/       JavaScript model, fixture, proof-link, and helper tests.
fixtures/    Small tally fixtures retained from the original AMACI flow.
spec/        Compatibility notes for the legacy migration surface.
```

Important current files:

- `src/fixtures/small-amaci-fixtures.mjs` builds the coherent small native
  round fixture.
- `tools/write-full-round-fixture.mjs` writes add-key, process-messages,
  tally, and chain-link input JSON files.
- `tools/run-stone-air.sh` builds minimal Cairo1 packages for Atlantic/Stone
  and writes `stone-air-run.json`.
- `src/atlantic/query-bundle.mjs` exports Atlantic-compatible `programFile`
  and `inputFile` bundles.
- `src/atlantic/mock-round-call.mjs` reconstructs Atlantic fact candidates and
  exports wrapper calls.
- `contracts/src/mock_amaci_round.cairo` consumes registered facts and updates
  round state.

## Quick Start

Install dependencies:

```sh
npm ci
```

Run the normal test suite:

```sh
npm test
npm run test:contracts
```

The current expected baseline is:

```text
npm test              147 passed, 11 skipped, 0 failed
npm run test:contracts 38 passed, 0 failed
```

Generate the coherent small native round fixture:

```sh
npm run write:full-round-fixture -- \
  --out-dir target/full-native-round-fixture \
  --text
```

This writes:

```text
add-new-key-native.json
process-messages-boundary-native.json
tally-native.json
chain.json
```

The process-messages fixture is also reused for the per-message component
circuits with `--message-index 0..4`.

## Preparing Native Circuit Inputs

Use the unified preparer for every supported native circuit:

```sh
npm run prepare:circuit -- \
  --circuit tally-native \
  fixtures/tally-small/000000.json \
  --out /tmp/zkstark-amaci-tally-native-prepared.json \
  --cairo-args-out /tmp/zkstark-amaci-tally-native-args.json
```

Examples for synthetic native circuits:

```sh
npm run prepare:add-new-key-native -- \
  --out /tmp/add-new-key-native-prepared.json

npm run prepare:process-message-step-core-native -- \
  --message-index 0 \
  --out /tmp/process-message-step-core-native-0-prepared.json

npm run prepare:process-deactivate-step-core-native -- \
  --message-index 0 \
  --out /tmp/process-deactivate-step-core-native-0-prepared.json
```

The preparer emits evaluated public fields, canonical public output, structured
Cairo input, and Scarb argument JSON when requested.

## Local Proof Paths

There are two local proof paths:

1. `scarb prove` / `scarb verify` for local Scarb/Stwo validation.
2. Stone AIR / Stone proof for Integrity and Atlantic compatibility.

Run all small native Scarb/Stwo proofs:

```sh
OUT_DIR=/absolute/path/to/zkstark-amaci-proofs

/usr/bin/time -v npm run prove:all-native-split-small -- \
  --tally-input fixtures/tally-small/000000.json \
  --out-dir "$OUT_DIR/all-native-split"
```

Run one native circuit proof:

```sh
npm run prove:tally-native -- --out-dir "$OUT_DIR/tally-native"
npm run prove:add-new-key-native -- --out-dir "$OUT_DIR/add-new-key-native"
npm run prove:process-message-step-core-native -- \
  --message-index 0 \
  --out-dir "$OUT_DIR/process-message-step-core-native-0"
npm run prove:process-deactivate-step-core-native -- \
  --message-index 0 \
  --out-dir "$OUT_DIR/process-deactivate-step-core-native-0"
```

The local Scarb/Stwo proof path is useful for development. For Starknet
application-layer verification today, use the Stone/Atlantic path below.

## Stone And Atlantic Path

Check the local Stone toolchain:

```sh
npm run check:stone-toolchain
```

Generate Atlantic-compatible AIR bundle inputs for one circuit:

```sh
CAIRO_CORELIB_DIR=~/cairo-vm/cairo1-run/corelib \
npm run stone:air:circuit -- \
  --circuit tally-native \
  --input fixtures/tally-small/000000.json \
  --out-dir /tmp/zkstark-amaci-stone/tally-native/stone-air \
  --skip-cairo1-run
```

For indexed component circuits:

```sh
CAIRO_CORELIB_DIR=~/cairo-vm/cairo1-run/corelib \
npm run stone:air:circuit -- \
  --circuit process-message-step-core-native \
  --message-index 0 \
  --out-dir /tmp/zkstark-amaci-stone/process-message-step-core-0/stone-air \
  --skip-cairo1-run
```

Export the Atlantic multipart bundle:

```sh
npm run export:atlantic-query -- \
  --stone-air-run /tmp/zkstark-amaci-stone/tally-native/stone-air/stone-air-run.json \
  --out-dir /tmp/zkstark-amaci-atlantic/tally-native \
  --network TESTNET \
  --text
```

The output directory contains:

```text
programFile   Cairo1 Sierra JSON for Atlantic
inputFile     Cairo1 Rust VM input for main(input: Array<felt252>)
submit-atlantic-query.sh
atlantic-query-bundle.json
```

Submit with an Atlantic API key:

```sh
ATLANTIC_API_KEY=... /tmp/zkstark-amaci-atlantic/tally-native/submit-atlantic-query.sh
```

Fetch the result and artifacts:

```sh
npm run atlantic:fetch-query -- \
  --query-id <atlantic-query-id> \
  --out-dir target/atlantic-query-check \
  --download-artifacts \
  --text
```

After the query reaches `DONE`, export a wrapper call:

```sh
npm run export:atlantic-round-call -- \
  --query-result target/atlantic-query-check/atlantic-query-result.json \
  --metadata target/atlantic-query-check/artifacts/metadata.json \
  --wrapper-address <MockAmaciRound-or-wrapper-address> \
  --profile <sncast-profile> \
  --out /tmp/atlantic-round-call.json \
  --text
```

## Starknet Wrappers

The `contracts/` package contains:

- `AddNewKeyStarkWrapper`
- `ProcessMessagesStarkWrapper`
- `ProcessDeactivateStarkWrapper`
- `TallyVotesStarkWrapper`
- `MockAmaciRound`
- `MockIntegrity`

The wrappers verify the registered Integrity fact shape and public output. The
mock round also tracks round state:

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

The full component E2E prototype follows this shape:

```text
deploy MockAmaciRound
  -> consume add-new-key-native fact
  -> consume process-message component facts
  -> consume process-messages-boundary-native fact
  -> consume tally-native fact
```

For the current small round, plaintext votes are local fixture data. The chain
stores and checks commitments/facts, not plaintext vote totals. Tally
correctness is established by:

```text
local fixture data
  -> JS evaluator computes expected native public fields
  -> Cairo native program recomputes and constrains those fields
  -> Atlantic verifies proof and registers Integrity fact on Starknet
  -> wrapper checks fact hash, program hash, verifier config/security bits, and public output
  -> wrapper updates the matching round commitment
```

## Fixture Support

The repository includes the small AMACI tally fixtures used during migration:

```text
fixtures/tally-small/000000.json
fixtures/tally-small/000001.json
fixtures/tally-small/000002.json
```

External operator fixtures can still be passed explicitly. Production operator
message inputs are discoverable, but the current native Cairo programs are
fixed to the small parameter set above and expect expanded synthetic witness
data for the split component proofs.

Run fixture discovery with:

```sh
npm run discover:fixtures -- fixtures/tally-small --validate \
  --out /tmp/zkstark-amaci-fixture-report.json
```

## Legacy Compatibility Code

The repository still contains legacy compatibility helpers and executable
targets for the original BN254 Poseidon/SHA-256 migration work. They are useful
for regression testing and for comparing the migration path, but the current
Starknet-oriented implementation uses the native circuit names ending in
`-native`.

## Generating Proofs On A High-Performance Machine

### Machine requirements

Use Linux/amd64 for the full proof run. The current macOS/arm64 machine can
compile, test, and execute the small programs, but proof generation has been
killed by the OS before completion.

Recommended starting point:

- Ubuntu 22.04 or 24.04 on amd64
- 16 or more CPU cores
- 64 GB RAM minimum for `tally` / `add-new-key`
- 128 GB RAM preferred for `process-messages` and `process-deactivate`
- fast local SSD/NVMe storage
- Node.js 20 or newer
- Scarb/Cairo toolchain compatible with `cairo/Scarb.toml`
  (`edition = "2024_07"`, Cairo/Scarb `2.18.0` in the current lockfile)
- `scarb execute`, `scarb prove`, and `scarb verify` available in the installed
  toolchain

### CLI Toolchain Install

The proof flow needs these command line tools:

- `git`: clone the standalone repository.
- `curl`, `ca-certificates`, `tar`, `unzip`: download and unpack toolchain
  installers.
- `build-essential`, `pkg-config`: baseline Linux build/runtime utilities used
  by npm dependencies and optional local builds.
- `node` and `npm`: run the JavaScript fixture/input/proof orchestration
  tools.
- `scarb`: compile, execute, prove, and verify the Cairo programs.

On a fresh Ubuntu 22.04/24.04 amd64 machine, run:

```sh
git clone https://github.com/DoraFactory/zkStark-amaci.git
cd zkStark-amaci
tools/install-proof-toolchain.sh
```

The script installs Node.js `20.x`, Scarb/Cairo `2.18.0`, this repository's npm
dependencies, and then checks:

```sh
scarb execute --help
scarb prove --help
scarb verify --help
```

Supported overrides:

```sh
NODE_MAJOR=22 tools/install-proof-toolchain.sh
SCARB_VERSION=2.18.0 tools/install-proof-toolchain.sh
tools/install-proof-toolchain.sh --skip-node
tools/install-proof-toolchain.sh --skip-scarb
tools/install-proof-toolchain.sh --skip-npm-install
```

If `scarb` is not visible in a new shell after installation, run:

```sh
source ~/.profile
```

Verify the toolchain before proving:

```sh
node --version
scarb --version
scarb execute --help
scarb prove --help
scarb verify --help
```

If any of the three Scarb subcommands are missing, the installed toolchain is
not sufficient for this proof path.

### Stone And Integrity Toolchain

The local proof installer above is enough for `scarb prove` and `scarb verify`.
It is not enough for the Stone/Integrity path. After local proofs work, check
the remaining tools:

```sh
npm run check:stone-toolchain
```

If it reports missing `cairo1-run`, `cpu_air_prover`, `cpu_air_verifier`, or
`cargo`, install the extra toolchain on the Linux/amd64 prover machine:

```sh
npm run install:stone-integrity-toolchain -- --install-docker
```

This script installs/builds the Stone-side tools:

- Rust/cargo, when missing.
- Stone prover `cpu_air_prover` and `cpu_air_verifier`, built through the
  upstream Stone Dockerfile.
- `cairo1-run`, built from `lambdaclass/cairo-vm`.

The build is heavier than the local Scarb installer and can take a long time.
If Docker is already installed and running, omit `--install-docker`:

```sh
npm run install:stone-integrity-toolchain
```

Useful overrides:

```sh
BIN_DIR=~/.local/bin npm run install:stone-integrity-toolchain
STONE_PROVER_DIR=~/stone-prover npm run install:stone-integrity-toolchain
CAIRO_VM_DIR=~/cairo-vm npm run install:stone-integrity-toolchain
STARKNET_TYPES_CORE_PACKAGE=starknet-types-core@0.1.8 npm run install:stone-integrity-toolchain
STARKNET_TYPES_CORE_VERSION=0.1.9 npm run install:stone-integrity-toolchain
npm run install:stone-integrity-toolchain -- --skip-stone
npm run install:stone-integrity-toolchain -- --skip-cairo1-run
```

If `cairo-vm/cairo1-run` fails while compiling `size-of 0.1.5` with
`"aapcs" is not a supported ABI for the current target`, first update
`starknet-types-core` within the compatible `^0.1.7` range and resume the
build:

```sh
cd ~/cairo-vm/cairo1-run
cargo update -p starknet-types-core@0.1.8 --precise 0.1.9
cargo build --release
```

If `cairo1-run` still leaves `size-of 0.1.5` in the build graph, apply the
local Linux/amd64 compatibility patch and retry the failed build:

```sh
SIZE_OF_DIR="$(find ~/.cargo/registry/src -type d -path '*/size-of-0.1.5' | head -n 1)"
cp "$SIZE_OF_DIR/src/core_impls.rs" "$SIZE_OF_DIR/src/core_impls.rs.zkstark-amaci.bak"
perl -0pi -e 's/impl_function_ptrs!\s*\{\s*"C",\s*"Rust",\s*"aapcs",\s*"cdecl",\s*"stdcall",\s*"fastcall",\s*\}/impl_function_ptrs! {\n    "C",\n    "Rust",\n}/s' "$SIZE_OF_DIR/src/core_impls.rs"
```

For `cairo1-run`, retry and link the binary if the installer did not finish:

```sh
cd ~/cairo-vm/cairo1-run
cargo build --release
mkdir -p ~/.local/bin
if [ -x ~/cairo-vm/target/release/cairo1-run ]; then
  ln -sf ~/cairo-vm/target/release/cairo1-run ~/.local/bin/cairo1-run
else
  ln -sf ~/cairo-vm/cairo1-run/target/release/cairo1-run ~/.local/bin/cairo1-run
fi
```

After installation, rerun:

```sh
npm run check:stone-toolchain
```

When all Stone/Integrity tools are `ok`, capture the exact CLI surfaces and
available Cairo artifacts before wiring the proof pipeline:

```sh
npm run inspect:stone-pipeline -- \
  --out-dir ~/zkstark-amaci-proofs/stone-inspect \
  --text
```

This writes `stone-pipeline-inspection.json` plus stdout/stderr captures for
`cairo1-run`, `cpu_air_prover`, and `cpu_air_verifier`.
For tally, the Stone path uses the native optimized circuit through the
proof-mode wrapper executable named `tally_votes_native_stone`. It accepts one
`Array<felt252>` input and returns one `Array<felt252>` public output because
`cairo1-run --proof_mode` only supports that input/output shape. Generate the
native tally AIR files with:

```sh
npm run stone:air:tally -- \
  --out-dir ~/zkstark-amaci-proofs/stone-tally-native/stone-air
```

`stone:air:tally` is an alias for the native circuit. The native default layout
is `recursive_with_poseidon`, because the optimized circuit uses the Starknet
Poseidon builtin. The old BN254/SHA tally Stone wrapper has been removed from
the exposed run path to avoid accidental legacy proof generation.

`cairo1-run` must be able to find a development `corelib`. The script checks
`CAIRO_CORELIB_DIR`, `CAIRO_VM_DIR`, and the default
`~/cairo-vm/cairo1-run/corelib` location created by `make deps`. If the runner
prints `Failed to find development corelib`, run:

```sh
cd ~/zkStark-amaci
CAIRO_CORELIB_DIR=~/cairo-vm/cairo1-run/corelib npm run stone:air:tally -- \
  --out-dir ~/zkstark-amaci-proofs/stone-tally-native/stone-air
```

If `~/cairo-vm/cairo1-run/corelib` is missing, create it with:

```sh
cd ~/cairo-vm/cairo1-run
make deps
```

This command prepares the small tally fixture, converts the Scarb executable
argument JSON into the bracketed decimal `cairo1-run --args_file` format,
builds a generated minimal Stone package under the output directory, exports a
`cairo1-run` Sierra artifact from that smaller package Sierra, renames the Stone
wrapper entrypoint to the `::main` suffix expected by `cairo1-run`, hides any
other package functions already ending in `::main`, runs `cairo1-run
--proof_mode`, and writes:

```text
trace.bin
memory.bin
air-public-input.json
air-private-input.json
stone-air-run.json
```

Do not pass `target/dev/tally_votes_native_stone.executable.json` directly to
`cairo1-run`. Scarb executable JSON is for the Scarb/cairo-execute runner; the
Stone AIR path uses the exported
`tally_votes_native_stone.cairo1-run.sierra.json`. The generated package is
intentionally narrow: it copies only the native tally modules needed by
`tally_votes_native_stone`, which avoids `cairo1-run` metadata
calculation over unrelated package functions.

The remaining Stone/Integrity path is:

```text
cpu_air_prover -> Stone proof JSON
cpu_air_verifier -> local Stone proof verification
integrity-calldata-generator -> Integrity split calldata
```

After `npm run stone:air:tally` succeeds, generate and locally verify the Stone
proof:

```sh
npm run stone:prove:tally -- \
  --air-run ~/zkstark-amaci-proofs/stone-tally-native/stone-air/stone-air-run.json \
  --out-dir ~/zkstark-amaci-proofs/stone-tally-native/stone-proof-integrity
```

By default this uses:

```text
~/stone-prover/cpu_air_prover_config.json
~/stone-prover/cpu_air_params.json
```

If `--parameter-file` is omitted, the script treats the detected
`cpu_air_params.json` as a template and writes a generated parameter file under
the proof output directory. The generated file adjusts `fri_step_list` so the
FRI degree matches the AIR `n_steps`, using Stone's required relation:

```text
log2(last_layer_degree_bound) + sum(fri_step_list) = ceil(log2(n_steps)) + 4
```

For the current tally small fixture this avoids the default
Fibonacci example mismatch where `[0, 4, 3]` and `last_layer_degree_bound=64`
only support FRI degree `2^13`, while the tally AIR can require a much larger
degree bound.

Generated params also default to the Integrity-compatible Stone profile:
Poseidon transcript, verifier-friendly Poseidon commitment layers, and
`keccak256_masked160_lsb` bottom commitments. This matches the default
`serialize:integrity-split-calldata --hasher keccak_160_lsb` setting. Passing
an explicit `--parameter-file` bypasses this profile; do that only for local
Stone verification experiments, not for Integrity/Starknet calldata.

If those files are not in the Stone checkout root, the script also checks the
official Stone example locations:

```text
~/stone-prover/e2e_test/Cairo/cpu_air_prover_config.json
~/stone-prover/e2e_test/Cairo/cpu_air_params.json
~/stone-prover/e2e_test/CairoZero/cpu_air_prover_config.json
~/stone-prover/e2e_test/CairoZero/cpu_air_params.json
```

Override those files if the trace size requires a different parameter file:

```sh
npm run stone:prove:tally -- \
  --air-run ~/zkstark-amaci-proofs/stone-tally-native/stone-air/stone-air-run.json \
  --out-dir ~/zkstark-amaci-proofs/stone-tally-native/stone-proof-integrity \
  --prover-config ~/stone-prover/e2e_test/Cairo/cpu_air_prover_config.json \
  --parameter-file ~/stone-prover/e2e_test/Cairo/cpu_air_params.json
```

The proof step writes:

```text
stone-proof.json
stone-prove.log
stone-verify.log
proof-run.json
```

Then run the Integrity readiness check against the Stone proof metadata:

```sh
npm run check:integrity -- \
  ~/zkstark-amaci-proofs/stone-tally-native-proof/proof-run.json \
  --program-hash 0x1234 \
  --proof-producer stone \
  --text
```

Do not pass the Scarb JSON args file directly to `cairo1-run`; use
`tools/convert-cairo1-run-args.mjs` or `npm run stone:air:tally`, because
`cairo1-run --args_file` expects whitespace-separated values and arrays are
written as `[1 2 3]`. Hex values from the Scarb argument JSON are converted to
decimal before calling `cairo1-run`.

### Repository Setup

If you already ran `tools/install-proof-toolchain.sh` from this repository, the
npm dependencies are already installed and you can continue to the preflight
checks below.

If you installed the CLI tools manually, clone the standalone proof repo and
install dependencies:

```sh
git clone https://github.com/DoraFactory/zkStark-amaci.git
cd zkStark-amaci
npm ci
```

### Tally Input

The tally proof needs a compatible AMACI `TallyVotes(2, 1, 1)` input JSON. The
fixture used during this migration is:

```text
fixtures/tally-small/000000.json
```

You can either use that checked-in fixture or point to your own compatible
tally input:

```sh
INPUT=fixtures/tally-small/000000.json
OUT_DIR=/absolute/path/to/proof-output
```

### Preflight checks

Run these before the expensive proof attempt. The execution test is optional
but strongly recommended because it exercises the actual Cairo executables
before proving.

```sh
npm test
npm run test:cairo-execute

cd cairo
scarb check
scarb test
scarb fmt --check
cd ..
```

Expected small execution characteristics on the current local machine:

- `tally_votes`: about `19,514,414` steps, `16` output felts.
- `add_new_key`: about `15,122,189` steps, `25` output felts.
- `process_messages_stateful_with_ecdh_signature`: about `163,029,062`
  steps, `24` output felts.
- `process_message_step_with_ecdh_signature`: one linked
  `ProcessMessages` message slot, `27` output felts. Use this when the dense
  five-message proof is too large for the current machine.
- `process_message_coord_key`: coordinator key binding, `10` output felts.
- `process_message_ecdh`: one message ECDH claim, `13` output felts.
- `process_message_signature`: one message EdDSA-Poseidon claim, `17`
  output felts.
- `process_message_step_core`: one message hash/state transition without
  repeated ECDH/signature scalar multiplication, `43` output felts.
- `process_deactivate_messages_stateful`: about `218,084,195` steps, `24`
  output felts.
- `process_deactivate_message_step`: one linked
  `ProcessDeactivateMessages` message slot, `31` output felts. Use this when
  the dense five-message deactivate proof is too large for the current
  machine.
- `process_deactivate_coord_key`: coordinator key binding, `10` output felts.
- `process_deactivate_ecdh`: command or deactivate-leaf ECDH claim, `14`
  output felts.
- `process_deactivate_signature`: one deactivate signature claim, `17`
  output felts.
- `process_deactivate_decrypt`: one current/new ElGamal decrypt parity claim,
  `16` output felts.
- `process_deactivate_step_core`: one deactivate message hash/root transition
  without repeated scalar multiplication or signature verification, `63`
  output felts.

If `scarb execute` fails, do not run the prover. Fix the input, toolchain, or
Cairo build first.

### Run All Native Small Proofs

Run the current native small proof flow:

```sh
INPUT=fixtures/tally-small/000000.json
OUT_DIR=/absolute/path/to/zkstark-amaci-proofs

/usr/bin/time -v npm run prove:all-native-split-small -- \
  --tally-input "$INPUT" \
  --out-dir "$OUT_DIR/all-native-split"
```

The script runs these circuits in order:

```text
tally-native
add-new-key-native
process-messages-native split
process-deactivate-native split
```

The non-tally inputs are generated from the current small synthetic fixtures.

### Run One Proof

Use these commands to isolate one circuit:

```sh
npm run prove:tally-native -- --out-dir "$OUT_DIR/tally-native"
npm run prove:add-new-key-native -- --out-dir "$OUT_DIR/add-new-key-native"
npm run prove:process-message-step-core-native -- \
  --message-index 0 \
  --out-dir "$OUT_DIR/process-message-step-core-native-0"
npm run prove:process-deactivate-step-core-native -- \
  --message-index 0 \
  --out-dir "$OUT_DIR/process-deactivate-step-core-native-0"
```

For Linux memory diagnostics, wrap any command with `/usr/bin/time -v`.

### Native Split ProcessMessages Proofs

Use the native split path for message processing:

```sh
/usr/bin/time -v npm run prove:process-messages-native-split -- \
  --out-dir "$OUT_DIR/process-messages-native-split"
```

This proves:

```text
process-messages-boundary-native
process-message-coord-key-native
process-message-ecdh-native --message-index 0..4
process-message-decrypt-native --message-index 0..4
process-message-signature-native --message-index 0..4
process-message-step-core-native --message-index 0..4
```

The deep split path lowers peak prover memory by moving the most expensive
BabyJubJub work out of the state-transition proof. The public outputs are
chainable: the boundary proof fixes the batch start/end hashes and state
commitments; `coord-key` binds `coordPubKeyHash` to `coordPrivKeyHash`; each
ECDH proof binds `coordPrivKeyHash + encPubKeyHash -> sharedKeyHash`; each
signature proof binds `pubKeyHash + R8Hash + packedCommandHash + S` to
`isSignatureValid`; and each core step exposes the same link hashes plus
`previous_message_hash`, `next_message_hash`, `current_state_root`, and
`new_state_root`. `MockAmaciRound` and the wrapper model consume these facts
for the current small-round cost prototype; production integration still needs
to connect the same checks to the real AMACI round state machine and operator
data model.

### Native Split ProcessDeactivate Proofs

Use the native split path for deactivate processing:

```sh
/usr/bin/time -v npm run prove:process-deactivate-native-split -- \
  --out-dir "$OUT_DIR/process-deactivate-native-split"
```

This proves:

```text
process-deactivate-boundary-native
process-deactivate-coord-key-native
process-deactivate-ecdh-command-native --message-index 0..4
process-deactivate-signature-native --message-index 0..4
process-deactivate-decrypt-current-native --message-index 0..4
process-deactivate-decrypt-new-native --message-index 0..4
process-deactivate-ecdh-leaf-native --message-index 0..4
process-deactivate-step-core-native --message-index 0..4
```

The deep split path moves the heavy BabyJubJub work out of the core root
transition. The core proof exposes link hashes for command ECDH, signature
verification, current/new ElGamal decrypt parity, deactivate-leaf ECDH, and
the same previous/next message hash plus active/deactivate root chain fields.
`MockAmaciRound` and the wrapper model support the native deactivate fact
shape; production integration still needs to connect those checks to real
round lifecycle rules, including deactivate index policy and operator data.

### Summarize Results

After execution or proof runs, summarize generated metadata with:

```sh
npm run summarize:proofs
```

For a custom output directory:

```sh
node tools/summarize-proof-results.mjs /absolute/path/to/proof-output --text
node tools/summarize-proof-results.mjs /absolute/path/to/proof-output \
  --out /tmp/zkstark-amaci-proof-summary.json
```

This reports discovered `proof-run.json` files, proof sizes, execution ids,
public output sizes, and any saved `scarb execute --print-resource-usage`
metadata. For full prover memory, keep wrapping proof commands with
`/usr/bin/time -v` because peak RSS is reported by the OS, not by Scarb.

### Proof Outputs

For each circuit, the script writes:

- `<circuit>-prepared.json`: parsed public fields, derived values, and
  canonical public output.
- `<circuit>-cairo-input.json`: structured Cairo input.
- `<circuit>-cairo-args.json`: `scarb prove --execute` argument file.
- `<circuit>-prove.log`: prover stdout/stderr.
- `<circuit>-verify.log`: verifier stdout/stderr.
- `proof-run.json`: circuit metadata, execution id, proof path, and generated
  input path when applicable.
- `cairo/target/execute/zkstark_amaci_tally/execution<id>/proof/proof.json`:
  generated local proof.

For `prove:all-native-split-small`, the root output directory contains:

```text
all-native-split-proofs.json
```

which points to the native tally proof, native add-new-key proof,
ProcessMessages native split metadata, and ProcessDeactivate native split
metadata.

The final command inside the script is:

```sh
scarb verify --execution-id <execution-id>
```

A successful run must complete that verification step without error for every
circuit.

### Useful result checks

After a successful run:

```sh
cat "$OUT_DIR/all-native-split/all-native-split-proofs.json"
cat "$OUT_DIR/all-native-split/tally-native/proof-run.json"
cat "$OUT_DIR/all-native-split/add-new-key-native/proof-run.json"
```

The `publicOutput.felts` in each `*-prepared.json` is the canonical output that
the Starknet wrapper will eventually bind to either a native proof transaction
or an Integrity fact.

### Native Starknet / S-two handoff

The current proof run already uses Scarb's local Stwo prover path:
`scarb prove --execute` followed by `scarb verify`. Use the native handoff
exporter first when targeting Starknet's in-protocol proof verification path:

```sh
npm run export:native-stwo-handoff -- \
  /absolute/path/to/all-native-split/tally-native/proof-run.json \
  --program-hash <real_tally_program_hash> \
  --out-dir /absolute/path/to/tally-native-stwo-handoff \
  --text
```

The handoff directory contains:

```text
native-handoff-manifest.json
native-readiness.json
native-proof-facts.json
public-output.json
proof-run.json
prepared.json
proof.json
prove.log
verify.log
```

`native-proof-facts.json` currently exports a candidate project-local binding:

```text
program_hash, public_output_hash, program_output_fact_hash
```

This separates three states that are easy to confuse:

- `localProofReady`: `scarb verify` accepted the Scarb/Stwo proof locally.
- `nativeHandoffReady`: the local proof and public-output binding are packaged.
- `nativeBroadcastReady`: the installed Starknet client stack exposes native
  `proof` / `proof_facts` transaction fields and this repo has mapped
  Scarb/Stwo `proof.json` into that transaction proof field.

With the current `starknet.js@6.24.1` dependency, the exporter should usually
report `Native handoff ready: yes` and `Native broadcast ready: no`. That means
the proof artifacts are ready for future native Starknet integration work,
but this repo is not yet submitting them as a mainnet transaction.

After a high-performance proof run, export a proof/executable inventory before
trying to derive native proof transaction fields:

```sh
npm run export:proof-inventory -- \
  /absolute/path/to/all-native-split \
  --target-dev cairo/target/dev \
  --out /absolute/path/to/proof-artifact-inventory.json \
  --text
```

The inventory records each `proof-run.json`, proof file hash, verify status,
prepared public-output count, and the matching
`cairo/target/dev/<executable>.executable.json` hash. Its
`localProgramDigest` is only a deterministic content digest of
`executable.program`; it is not a canonical Starknet native `proof_facts`
program hash.

### Stone / Integrity fallback handoff

Check whether a tally proof run has enough metadata for the next Integrity
step:

```sh
npm run check:integrity -- \
  "$STONE_PROOF_DIR/proof-run.json" \
  --program-hash <tally_program_hash> \
  --text
```

This command separates two questions:

- whether the wrapper binding hash can be computed from
  `program_hash + publicOutput`;
- whether the proof run already contains Stone/Integrity proof calldata that
  can be submitted to a FactRegistry flow.
- whether the local `scarb verify` step succeeded for the generated
  Scarb/Stwo proof artifact.

The current `scarb prove --execute` metadata is marked as
`proofProducer = scarb-stwo-local`, so it is valid for local proof generation
and `scarb verify`, but it is not treated as directly ready for Integrity
submission until a Stone/Integrity-compatible proof calldata artifact is
provided.

`tools/run-stone.sh` is intentionally not a pass-through alias for
`scarb prove`. Use it only to check whether a machine has the missing Stone
toolchain pieces:

```sh
npm run check:stone-toolchain
```

For a real Integrity path, the missing artifact is a Stone proof produced from
Cairo AIR inputs, not the Scarb/Stwo `proof.json` under `cairo/target/execute`.
That means the next integration step must add or supply:

- `cairo1-run` proof-mode execution that emits trace, memory, AIR public input,
  and AIR private input for the selected Cairo executable;
- `cpu_air_prover` and `cpu_air_verifier` over those AIR files;
- Herodotus `integrity-calldata-generator` split calldata for the Stone proof.

The expected intermediate result for the current local Scarb/Stwo proof path
is:

```text
Local scarb verification: yes
Local proof ready: yes
Local wrapper binding ready: yes
Integrity submission ready: no
```

To mark a proof run as Integrity-ready, rerun the checker only after producing
Stone/Integrity-compatible calldata. The native tally Stone proof uses
`recursive_with_poseidon`, so use split calldata:

Integrity's split calldata generator expects verifier-side Stone annotations,
including OODS values. `npm run stone:prove:tally` now runs
`cpu_air_verifier --annotation_file --extra_output_file` after proving and
rewrites `$STONE_OUT/stone-proof-integrity/stone-proof.json` with those verifier
annotations. If an older `stone-proof.json` fails with `missing field
annotations`, `annotations are incomplete`, or
`Commit(Oods(EvaluationInvalid ...))`, rerun only the Stone proof step against
the existing AIR run so it uses the generated Integrity-compatible params:

Some Stone verifier builds emit OODS values as repeated `Field Element(...)`
annotation lines instead of one `Field Elements(...)` span. The split calldata
wrapper normalizes that form automatically and writes
`$STONE_OUT/integrity-split/stone-proof.integrity-normalized.json` for the
serializer when needed.

```sh
npm run stone:prove:tally -- \
  --air-run "$STONE_OUT/stone-air/stone-air-run.json" \
  --out-dir "$STONE_OUT/stone-proof-integrity"
```

```sh
export STONE_OUT=/data/zkstark-amaci-proofs/stone-native-tally-20260516-144921
export STONE_PROOF_DIR="$STONE_OUT/stone-proof-integrity"

npm run serialize:integrity-split-calldata -- \
  --stone-proof "$STONE_PROOF_DIR/stone-proof.json" \
  --calldata-generator ~/integrity-calldata-generator \
  --out-dir "$STONE_OUT/integrity-split" \
  --out "$STONE_OUT/integrity-split-calldata.json" \
  --layout recursive_with_poseidon \
  --hasher keccak_160_lsb \
  --stone-version stone6 \
  --memory-verification cairo1 \
  --text
```

If split calldata has already been generated, wrap it without regenerating:

```sh
npm run serialize:integrity-split-calldata -- \
  --split-calldata-dir "$STONE_OUT/integrity-split/split-calldata" \
  --out "$STONE_OUT/integrity-split-calldata.json" \
  --layout recursive_with_poseidon \
  --hasher keccak_160_lsb \
  --stone-version stone6 \
  --memory-verification cairo1 \
  --text
```

Then rerun the checker:

```sh
npm run inspect:stone-fact -- \
  --stone-proof "$STONE_PROOF_DIR/stone-proof.json" \
  --out "$STONE_OUT/stone-fact.json" \
  --text

PROGRAM_HASH=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).programHash)' "$STONE_OUT/stone-fact.json")
FACT_HASH=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).factHash)' "$STONE_OUT/stone-fact.json")
VERIFIER_CONFIG_HASH=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).settings.verifierConfigHash)' "$STONE_OUT/integrity-split-calldata.json")

npm run check:integrity -- \
  "$STONE_PROOF_DIR/proof-run.json" \
  --program-hash "$PROGRAM_HASH" \
  --proof-producer stone \
  --integrity-calldata "$STONE_OUT/integrity-split-calldata.json" \
  --verifier-config-hash "$VERIFIER_CONFIG_HASH" \
  --security-bits <security_bits> \
  --text
```

Do not pass the current `scarb prove` / Scarb-Stwo `proof.json` as
`--stone-proof`; Integrity verifies Stone prover proofs and the serializer
expects that proof format. The exact current native Stone/Integrity command
sequence is recorded in `docs/native-stone-integrity-runbook.md`.

After split calldata is ready, prepare or send the FactRegistry transactions:

```sh
npm run submit:integrity-fact -- \
  --split-calldata "$STONE_OUT/integrity-split-calldata.json" \
  --network sepolia \
  --job-id 20260516144921 \
  --fact-hash "$FACT_HASH" \
  --verification-hash <expected_verification_hash> \
  --program-hash "$PROGRAM_HASH" \
  --verifier-config-hash "$VERIFIER_CONFIG_HASH" \
  --security-bits <security_bits> \
  --out "$STONE_OUT/integrity-submission.json" \
  --text
```

The command above is a dry run. Add `--send` only after `sncast` is configured
with the target account and RPC. The split flow sends
`verify_proof_initial`, each `verify_proof_step`, and
`verify_proof_final_and_register_fact`.

Finally export the AMACI wrapper call:

```sh
npm run export:wrapper-call -- \
  "$STONE_PROOF_DIR/proof-run.json" \
  --program-hash "$PROGRAM_HASH" \
  --verifier-config-hash "$VERIFIER_CONFIG_HASH" \
  --security-bits <security_bits> \
  --proof-producer stone \
  --integrity-calldata "$STONE_OUT/integrity-split-calldata.json" \
  --wrapper-address <deployed_amaci_wrapper_address> \
  --out "$STONE_OUT/wrapper-call.json" \
  --text
```

The native tally wrapper checks that the supplied `fact_hash` equals the hash
derived from the pinned program hash and the native public output
(`new_tally_commitment` and `input_hash` included), then checks Integrity. If a
non-zero `verifier_config_hash` was configured in the wrapper constructor, it
checks the exact `verification_hash`; otherwise it falls back to
`is_fact_hash_valid_with_security`.

You can also export a self-contained handoff package for the next
Stone/Integrity integration step:

```sh
npm run export:integrity-handoff -- \
  "$STONE_PROOF_DIR/proof-run.json" \
  --program-hash "$PROGRAM_HASH" \
  --proof-producer stone \
  --integrity-calldata "$STONE_OUT/integrity-split-calldata.json" \
  --out-dir /absolute/path/to/tally-integrity-handoff \
  --text
```

The handoff directory contains:

```text
handoff-manifest.json
integrity-readiness.json
public-output.json
wrapper-fact.json
proof-run.json
prepared.json
proof.json
verify.log
```

For tally, the encoding is:

```text
magic, version, circuit_id,
state_tree_depth, int_state_tree_depth, vote_option_tree_depth,
packed_vals_low128, packed_vals_high128,
state_commitment_low128, state_commitment_high128,
current_tally_commitment_low128, current_tally_commitment_high128,
new_tally_commitment_low128, new_tally_commitment_high128,
input_hash_low128, input_hash_high128
```

### Known limits of this proof run

- This validates the current small-parameter PoC only.
- `TallyVotes(2,1,1)` can use the existing small AMACI tally fixture.
- `AddNewKey(2)`, `ProcessMessages(2,1,5)`, and
  `ProcessDeactivateMessages(2,5)` use synthetic fixtures that exercise the
  native split relation for those small parameters.
- Production-size `9-4-3-125` targets are not generated or proven by this
  flow.
- Real operator fixture cross-checking for non-tally circuits is still pending.
- It does not replace AMACI's internal non-PQ cryptography yet.
- Application-layer Starknet verification currently goes through
  Stone/Atlantic/Integrity registered facts. Direct Starknet native Stwo
  proof transaction submission remains an experimental handoff path.
- The stateful Cairo paths now short-circuit empty message slots at runtime, so
  empty slots skip ECDH/signature/decrypt/state-update work. The checked-in
  small synthetic `ProcessMessages` and `ProcessDeactivateMessages` fixtures
  currently use five non-empty messages, so this optimization affects sparse
  batches but does not reduce the dense five-message benchmark.
- Dense `ProcessMessages(2,1,5)` and `ProcessDeactivateMessages(2,5)` both
  have deep split proof paths and wrapper-side fact shapes. The current E2E
  contract is still a mock round used for validation and cost measurement, not
  the final production AMACI contract.

## Commands

From this directory:

```sh
npm test
npm run test:msg
node tools/prepare-ecdh-input.mjs \
  <ecdh-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-ecdh-args.json
cd cairo
scarb execute \
  --executable-name ecdh_shared_key \
  --arguments-file /tmp/zkstark-amaci-ecdh-args.json \
  --print-program-output
cd ..
node tools/prepare-process-one-with-ecdh-input.mjs \
  <process-one-input.json> \
  <ecdh-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-process-one-with-ecdh-args.json
cd cairo
scarb execute \
  --executable-name process_one_with_ecdh \
  --arguments-file /tmp/zkstark-amaci-process-one-with-ecdh-args.json \
  --print-program-output
cd ..
node tools/prepare-tally-input.mjs \
  fixtures/tally-small/000000.json
node tools/prepare-process-messages-input.mjs <process-messages-input.json>
node tools/prepare-process-messages-input.mjs \
  <process-messages-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-msg-cairo-args.json
cd cairo
scarb execute \
  --executable-name process_messages_boundary \
  --arguments-file /tmp/zkstark-amaci-msg-cairo-args.json \
  --print-program-output
cd ..
node tools/prepare-process-one-input.mjs \
  <process-one-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-process-one-args.json
cd cairo
scarb execute \
  --executable-name process_one_state_transition \
  --arguments-file /tmp/zkstark-amaci-process-one-args.json \
  --print-program-output
cd ..
node tools/prepare-process-messages-state-input.mjs \
  <process-messages-state-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-process-messages-state-args.json
cd cairo
scarb execute \
  --executable-name process_messages_state_transition \
  --arguments-file /tmp/zkstark-amaci-process-messages-state-args.json \
  --print-program-output
cd ..
node tools/prepare-process-messages-stateful-input.mjs \
  <process-messages-stateful-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-process-messages-stateful-args.json
cd cairo
scarb execute \
  --executable-name process_messages_stateful \
  --arguments-file /tmp/zkstark-amaci-process-messages-stateful-args.json \
  --print-program-output
cd ..
node tools/prepare-process-messages-stateful-with-ecdh-input.mjs \
  <process-messages-stateful-ecdh-input.json> \
  --cairo-args-out /tmp/zkstark-amaci-process-messages-stateful-ecdh-args.json
cd cairo
scarb execute \
  --executable-name process_messages_stateful_with_ecdh \
  --arguments-file /tmp/zkstark-amaci-process-messages-stateful-ecdh-args.json \
  --print-program-output
cd ..
node tools/prepare-tally-input.mjs \
  fixtures/tally-small/000000.json \
  --cairo-input-out /tmp/zkstark-amaci-cairo-input.json
node tools/export-hash-vectors.mjs \
  fixtures/tally-small/000000.json \
  --out /tmp/zkstark-amaci-hash-vectors.json
node tools/verify-hash-vectors.mjs /tmp/zkstark-amaci-hash-vectors.json
```

With a compiled Cairo child program hash:

```sh
node tools/prepare-tally-input.mjs \
  fixtures/tally-small/000000.json \
  --program-hash 0x1234
```

For wrapper-binding development, the JavaScript model in `src/wrapper/` checks
the same state transition the Starknet wrapper should enforce: the submitted
fact must be registered in Integrity with enough security bits and must bind to
the fixed program hash plus canonical public output.

The Cairo/STARK toolchain is not vendored here. Install `scarb` with
`scarb execute`, `scarb prove`, and `scarb verify` support before running the
local proof path. Stone/Integrity tooling is still needed for the Starknet
FactRegistry submission path.
