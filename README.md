# zkStark-amaci

Parallel Stark/STARK proof-layer prototype for AMACI.

This repository is intentionally independent from the existing Circom,
CosmWasm, SDK, and operator code. The first completed milestone targets the
`TallyVotes` relation for the small parameter set:

- `stateTreeDepth = 2`
- `intStateTreeDepth = 1`
- `voteOptionTreeDepth = 1`

The current work-in-progress target also covers the first
`ProcessMessages(2, 1, 5)` and `ProcessDeactivateMessages(2, 5)` migration
slices.

The implementation keeps the existing AMACI public-input semantics:

- BN254 scalar field values are represented as unsigned 256-bit integers.
- Poseidon uses the same Circom-compatible parameters as the existing
  circuits.
- AMACI state leaves use the existing `Hasher10` composition:
  `HashLeftRight(Hasher5(first 5 fields), Hasher5(last 5 fields))`.
- `inputHash = sha256(packedVals, stateCommitment, currentTallyCommitment,
  newTallyCommitment) mod BN254_SCALAR_FIELD`.
- Public output uses a fixed felt list with `u256` values split as
  `low128, high128`.

## What is implemented

- `spec/tally-votes-compat.md`, `spec/process-messages-compat.md`,
  `spec/add-new-key-compat.md`, and `spec/process-deactivate-compat.md`
  document the migrated AMACI compatibility contracts.
- `src/` contains a deterministic JavaScript reference implementation for the
  `TallyVotes` relation and public-output encoding.
- `src/compat/poseidon-bn254.mjs` contains a pure JavaScript implementation of
  the same BN254 Poseidon permutation used by the existing Circom package. It
  is used to generate and verify the Cairo Poseidon constants and test vectors.
- `tools/prepare-tally-input.mjs` validates an existing tally input JSON and
  emits canonical public output, fixed-size Cairo program input, plus optional
  Integrity fact hashes when a program hash is supplied.
- `fixtures/tally-small/` vendors the small AMACI tally fixtures used for
  standalone testing and proof generation.
- `tests/` exercises valid and invalid tally inputs against those AMACI
  fixtures with 10-field state leaves.
- `cairo/` contains the first fixed-size `TallyVotes(2, 1, 1)` Cairo relation
  migration. It computes AMACI `Hasher10`, Circom-compatible BN254 Poseidon
  T3/T6, quinary tree hashes, and the SHA-256 `inputHash` inside Cairo, while
  retaining hash claims only as witness compatibility assertions against the
  generated input. It also contains the initial
  `ProcessMessages(2, 1, 5)` public-boundary executable.
- `contracts/` contains the Starknet target scaffolding for the Integrity
  wrapper.
- `spec/process-messages-compat.md`, `src/msg/`, and the Cairo
  `process_messages_boundary` executable start the next migration target by
  pinning the `ProcessMessages(2, 1, 5)` public-input contract, packed values,
  message hash chain, and canonical public output. They also include the first
  `ProcessOne` migration slice: encrypted message binding,
  Circom-compatible `PoseidonDecryptWithoutCheck(7)` over `msg[10]` and a
  witness `sharedKey[2]`, decrypted-command field mapping, `packedCommand`
  unpacking, deterministic `MessageValidator` constraints,
  BabyJubJub signature binding, ElGamal active-state decrypt binding,
  state-leaf inclusion, active-state inclusion, vote-option root update, and
  new state-root derivation for the fixed
  `(stateTreeDepth=2, voteOptionTreeDepth=1)` parameters. The
  `process_messages_state_transition` executable chains five
  `ProcessOne` witnesses in AMACI's reverse batch order into the
  `ProcessMessages(2, 1, 5)` state-root transition, and
  `process_messages_stateful` binds that transition back to the public
  boundary and canonical public output, including empty-message handling,
  boundary message matching, and boundary parameter matching for each
  `ProcessOne` witness. The boundary now follows the current AMACI Circom
  public hash shape:
  message length `10`, message chain `Hasher13`, and
  `Sha256Hasher(8)` with `expectedPollId`.
- `src/compat/babyjub.mjs`, `tools/prepare-ecdh-input.mjs`, and the Cairo
  `ecdh_shared_key` executable implement the first standalone ECDH migration
  slice: BabyJubJub scalar multiplication is checked with a fixed 253-step
  transcript, matching the existing `@zk-kit/baby-jubjub` result.
- `tools/prepare-process-one-with-ecdh-input.mjs` and the Cairo
  `process_one_with_ecdh` executable close the first single-message path:
  ECDH transcript output must equal `ProcessOne.sharedKey`, then the same
  shared key is used for Poseidon command decryption and the migrated
  `ProcessOne` state transition.
- `tools/prepare-process-messages-stateful-with-ecdh-input.mjs` and the Cairo
  `process_messages_stateful_with_ecdh` executable wire that ECDH binding into
  the fixed five-message batch: each non-empty boundary `encPubKey[2]` must be
  the base point for an ECDH transcript using the same `coordPrivKey`, and the
  transcript output must match the corresponding `ProcessOne.sharedKey`. The
  same executable also proves
  `PrivToPubKey(coordPrivKey) == coordPubKey` against the public boundary's
  coordinator key.
- `buildCairoBabyjubPoseidonSignatureInput` and the Cairo `verify_signature`
  executable implement the standalone AMACI `VerifySignature` primitive:
  `M = Poseidon(packedCommand[0..2])`, then
  `S * Base8 == R8 + Poseidon(R8, A, M) * (8 * A)`.
- `process_one_with_signature` and `process_one_with_ecdh_signature` wire that
  signature result into one `ProcessOne` witness, so `isSignatureValid` can be
  derived inside Cairo for a single decrypted message.
- `process_messages_stateful_with_ecdh_signature` extends the five-message
  stateful path with per-message signature witnesses, while keeping the
  ECDH-only executable available for smaller compatibility checks.
- `process_message_step_with_ecdh_signature` exposes a linked single-message
  proof path for dense-batch debugging: each step proves one message hash
  transition, coordinator key binding, ECDH shared key, signature check,
  active-state decrypt parity, and state-root update. Its public output
  carries the previous/next message hashes, previous/next state roots, and
  current/new state commitments so a wrapper or off-chain checker can chain
  five smaller proofs with one boundary proof.
- The preferred ProcessMessages split path now uses smaller linked pieces:
  `process_message_coord_key`, per-message `process_message_ecdh`,
  per-message `process_message_signature`, and per-message
  `process_message_step_core`. The core step no longer repeats coordinator
  public-key derivation, ECDH, or EdDSA scalar multiplication; it exposes
  hash links for `coordPrivKey`, `encPubKey`, shared key, signature pubkey,
  `R8`, packed command, `S`, and `isSignatureValid`, so a wrapper can chain
  the smaller facts.
- `src/add-new-key/`, `tools/prepare-add-new-key-input.mjs`, and the Cairo
  `add_new_key` executable start the next circuit migration target:
  `AddNewKey(stateTreeDepth=2)`. The compatibility relation verifies the
  round nullifier, ECDH-derived deactivate leaf, depth-4 deactivate tree
  inclusion, ElGamal re-randomization, `Sha256Hasher(9)` input hash, and
  canonical public output.
- `src/deactivate/`, `tools/prepare-process-deactivate-one-input.mjs`,
  `tools/prepare-process-deactivate-boundary-input.mjs`,
  `tools/prepare-process-deactivate-stateful-input.mjs`, and the Cairo
  `process_deactivate_one` / `process_deactivate_messages_boundary` /
  `process_deactivate_messages_state_transition` /
  `process_deactivate_messages_stateful`
  executables start the `ProcessDeactivateMessages(2, 5)` migration target.
  The single-message slice verifies EdDSA-Poseidon, ElGamal decrypt parity for
  the current active flag and new deactivate ciphertext, state-root inclusion,
  active-state root update, deactivate-tree insertion, ECDH-derived deactivate
  leaf, and non-zero `newActiveState`. The boundary slice verifies
  `Sha256Hasher(8)`, current deactivate commitment, canonical public output,
  and the deactivate message hash chain where empty messages are detected by
  `msg[0] == 0`. The stateful slice chains five `ProcessOne` witnesses in
  forward order, binds `coordPrivKey` to the public `coordPubKey`, checks
  final `newDeactivateRoot`, recomputes `newDeactivateCommitment`, and binds
  every non-empty boundary encrypted message and `encPubKey` to its
  `ProcessOne` command fields through ECDH and
  `PoseidonDecryptWithoutCheck(7)`.
  The preferred split path also exposes smaller deactivate slices:
  `process_deactivate_coord_key`, per-message command ECDH, per-message
  signature, current/new ElGamal decrypt parity, deactivate-leaf ECDH, and a
  `process_deactivate_step_core` proof that links those claims to the root
  transition.
- `src/fixtures/` and `tools/discover-amaci-fixtures.mjs` classify existing
  AMACI operator JSON fixtures and report which ones are directly runnable by
  the current small-parameter Cairo targets.
- `tools/prepare-amaci-circuit-input.mjs` is the unified offline input
  preparer for all currently migrated circuit slices. It emits evaluated public
  fields, canonical public output, structured Cairo input, and
  `scarb execute --arguments-file` JSON.
- `src/wrapper/amaci-wrapper-model.mjs` models the intended Starknet wrapper
  checks for all migrated circuit families: fixed program hash, canonical
  public output, Integrity fact hash, optional verification hash, and wrapper
  state updates for tally, process-message, deactivate, and add-new-key flows.

## Fixture support status

The repository includes the small AMACI tally fixtures used during the
migration:

```text
fixtures/tally-small/000000.json
fixtures/tally-small/000001.json
fixtures/tally-small/000002.json
```

External operator fixtures are still supported as explicit input paths, but
this standalone repo no longer assumes a sibling `amaci-operator` checkout.
Production `msg_inputs/*.json` fixtures are discoverable and classified when
you provide them, but they are not directly runnable yet because the current
Cairo migration is fixed to `ProcessMessages(2, 1, 5)` /
`ProcessDeactivateMessages(2, 5)` and expects prepared
`processOneWitnesses`. The production operator message inputs use larger
parameters and do not include those expanded witnesses in the shape needed by
these small Cairo executables.

Run fixture discovery with:

```sh
npm run discover:fixtures -- fixtures/tally-small --validate \
  --out /tmp/zkstark-amaci-fixture-report.json
```

Prepare any supported circuit input through the unified CLI:

```sh
npm run prepare:circuit -- \
  --circuit tally \
  fixtures/tally-small/000000.json \
  --out /tmp/zkstark-amaci-tally-prepared.json \
  --cairo-args-out /tmp/zkstark-amaci-tally-args.json
```

Run small synthetic fixtures through the actual Cairo executables with:

```sh
npm run execute:circuit -- --circuit add-new-key
npm run execute:circuit -- --circuit process-messages
npm run execute:circuit -- --circuit process-deactivate
```

These commands generate the current small fixture when no input path is
provided, prepare Cairo arguments, run `scarb execute`, and write metadata plus
stdout/stderr under `target/cairo-execute/<circuit>/`.

The corresponding execution test is intentionally opt-in because these paths
are much heavier than normal unit tests:

```sh
npm run test:cairo-execute
```

## Current proof status

The local Cairo execution flow succeeds for the existing AMACI fixture:

```text
fixtures/tally-small/000000.json
```

Execute locally with:

```sh
npm run prepare:cairo-args
cd cairo
scarb execute \
  --executable-name tally_votes \
  --arguments-file /tmp/zkstark-amaci-cairo-args.json \
  --print-program-output
```

The current AMACI execution is intentionally small-parameter and expensive:

- Cairo execution steps: `19,514,414`
- max memory address: `27,947,371`
- range-check builtin uses: `5,139,640`
- bitwise builtin uses: `2,880`
- output felts: `16`

This executes the migrated AMACI `TallyVotes(2, 1, 1)` relation locally. A full
local proof attempt with `npm run prove:tally` currently reaches
`scarb prove --execute` and is then killed by this macOS/arm64 machine with
exit code `137` / `Killed: 9`. The relation implementation is therefore
validated by execution and tests, but AMACI local proving needs a larger
Linux/amd64 machine or CI runner. Integrity proof serialization, a pinned
FactRegistry interface, and wrapper deployment/testing are still open.

## Generating Proofs On A High-Performance Machine

This is the current end-to-end local proof validation path for the migrated
small-parameter AMACI Cairo programs:

- `TallyVotes(2, 1, 1)` with the existing AMACI tally fixture.
- `AddNewKey(stateTreeDepth=2)` with the current small synthetic fixture.
- `ProcessMessages(2, 1, 5)` with the current full ECDH+signature synthetic
  fixture.
- `ProcessDeactivateMessages(2, 5)` with the current full stateful synthetic
  fixture.

This flow does not submit anything to Starknet or Integrity yet. Success means:

1. each input is converted into canonical Cairo arguments,
2. `scarb prove --execute` generates a local STARK proof for each Cairo
   executable,
3. `scarb verify` verifies every generated proof locally.

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

If it reports missing `cairo1-run`, `cpu_air_prover`, `cpu_air_verifier`,
`proof_serializer`, or `cargo`, install the extra toolchain on the
Linux/amd64 prover machine:

```sh
npm run install:stone-integrity-toolchain -- --install-docker
```

This script installs/builds:

- Rust/cargo, when missing.
- Stone prover `cpu_air_prover` and `cpu_air_verifier`, built through the
  upstream Stone Dockerfile.
- `cairo1-run`, built from `lambdaclass/cairo-vm`.
- Herodotus Integrity `proof_serializer`, built from
  `HerodotusDev/integrity`.

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
INTEGRITY_DIR=~/integrity npm run install:stone-integrity-toolchain
STARKNET_TYPES_CORE_PACKAGE=starknet-types-core@0.1.8 npm run install:stone-integrity-toolchain
STARKNET_TYPES_CORE_VERSION=0.1.9 npm run install:stone-integrity-toolchain
npm run install:stone-integrity-toolchain -- --skip-stone
npm run install:stone-integrity-toolchain -- --skip-cairo1-run
npm run install:stone-integrity-toolchain -- --skip-integrity
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

If `cairo1-run` or Integrity `proof_serializer` still leaves `size-of 0.1.5`
in the build graph, apply the local Linux/amd64 compatibility patch and retry
the failed build:

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

For Integrity `proof_serializer`, retry and link the binary:

```sh
cd ~/integrity
cargo build --release --bin proof_serializer
mkdir -p ~/.local/bin
ln -sf ~/integrity/target/release/proof_serializer ~/.local/bin/proof_serializer
```

If `proof_serializer` then fails in `cairo-vm 1.0.2` with
`is_multiple_of(&...)` type errors, patch the legacy calls for the current
Rust toolchain and retry:

```sh
CAIRO_VM_102="$(find ~/.cargo/registry/src -type d -path '*/cairo-vm-1.0.2' | head -n 1)"
perl -0pi -e 's/\.is_multiple_of\(&\(CELLS_PER_SIGNATURE as usize\)\)/.is_multiple_of(CELLS_PER_SIGNATURE as usize)/g' \
  "$CAIRO_VM_102/src/hint_processor/builtin_hint_processor/signature.rs"
perl -0pi -e 's/\.is_multiple_of\(&CELL_BYTE_LEN\)/.is_multiple_of(CELL_BYTE_LEN)/g' \
  "$CAIRO_VM_102/src/vm/runners/cairo_pie.rs"

cd ~/integrity
cargo clean -p cairo-vm
cargo build --release --bin proof_serializer
ln -sf ~/integrity/target/release/proof_serializer ~/.local/bin/proof_serializer
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
`cairo1-run`, `cpu_air_prover`, `cpu_air_verifier`, and `proof_serializer`.
For tally, the repository includes a proof-mode wrapper executable named
`tally_votes_stone`. It accepts one `Array<felt252>` input and returns one
`Array<felt252>` public output because `cairo1-run --proof_mode` only supports
that input/output shape. Generate the tally AIR files with:

```sh
npm run stone:air:tally -- \
  --out-dir ~/zkstark-amaci-proofs/stone-tally
```

This command prepares the small tally fixture, converts the Scarb executable
argument JSON into the bracketed decimal `cairo1-run --args_file` format, runs
`cairo1-run --proof_mode`, and writes:

```text
trace.bin
memory.bin
air-public-input.json
air-private-input.json
stone-air-run.json
```

The remaining Stone/Integrity path is:

```text
cpu_air_prover -> Stone proof JSON
cpu_air_verifier -> local Stone proof verification
proof_serializer -> Integrity calldata
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

### Run All Small Proofs

Run all four current small proof flows:

```sh
INPUT=fixtures/tally-small/000000.json
OUT_DIR=/absolute/path/to/zkstark-amaci-proofs

/usr/bin/time -v tools/run-cairo-proof.sh \
  --all \
  --tally-input "$INPUT" \
  --out-dir "$OUT_DIR"
```

The standalone npm shortcut uses the checked-in tally fixture:

```sh
npm run prove:all-small
```

For the optimized split path, prefer:

```sh
/usr/bin/time -v npm run prove:all-split-small -- \
  --out-dir "$OUT_DIR/all-split"
```

The script runs these circuits in order:

```text
tally
add-new-key
process-messages
process-deactivate
```

The non-tally inputs are generated from the current small synthetic fixtures.

### Run One Proof

Use these commands to isolate one circuit:

```sh
tools/run-cairo-proof.sh --circuit tally --input "$INPUT" --out-dir "$OUT_DIR/tally"
tools/run-cairo-proof.sh --circuit add-new-key --out-dir "$OUT_DIR/add-new-key"
tools/run-cairo-proof.sh --circuit process-messages --out-dir "$OUT_DIR/process-messages"
tools/run-cairo-proof.sh --circuit process-messages-boundary --out-dir "$OUT_DIR/process-messages-boundary"
tools/run-cairo-proof.sh --circuit process-message-step --message-index 0 --out-dir "$OUT_DIR/process-message-step-0"
tools/run-cairo-proof.sh --circuit process-message-coord-key --out-dir "$OUT_DIR/process-message-coord-key"
tools/run-cairo-proof.sh --circuit process-message-ecdh --message-index 0 --out-dir "$OUT_DIR/process-message-ecdh-0"
tools/run-cairo-proof.sh --circuit process-message-signature --message-index 0 --out-dir "$OUT_DIR/process-message-signature-0"
tools/run-cairo-proof.sh --circuit process-message-step-core --message-index 0 --out-dir "$OUT_DIR/process-message-step-core-0"
tools/run-cairo-proof.sh --circuit process-deactivate --out-dir "$OUT_DIR/process-deactivate"
tools/run-cairo-proof.sh --circuit process-deactivate-boundary --out-dir "$OUT_DIR/process-deactivate-boundary"
tools/run-cairo-proof.sh --circuit process-deactivate-step --message-index 0 --out-dir "$OUT_DIR/process-deactivate-step-0"
tools/run-cairo-proof.sh --circuit process-deactivate-coord-key --out-dir "$OUT_DIR/process-deactivate-coord-key"
tools/run-cairo-proof.sh --circuit process-deactivate-ecdh-command --message-index 0 --out-dir "$OUT_DIR/process-deactivate-command-ecdh-0"
tools/run-cairo-proof.sh --circuit process-deactivate-signature --message-index 0 --out-dir "$OUT_DIR/process-deactivate-signature-0"
tools/run-cairo-proof.sh --circuit process-deactivate-decrypt-current --message-index 0 --out-dir "$OUT_DIR/process-deactivate-current-decrypt-0"
tools/run-cairo-proof.sh --circuit process-deactivate-decrypt-new --message-index 0 --out-dir "$OUT_DIR/process-deactivate-new-decrypt-0"
tools/run-cairo-proof.sh --circuit process-deactivate-ecdh-leaf --message-index 0 --out-dir "$OUT_DIR/process-deactivate-leaf-ecdh-0"
tools/run-cairo-proof.sh --circuit process-deactivate-step-core --message-index 0 --out-dir "$OUT_DIR/process-deactivate-step-core-0"
```

The legacy tally-only form is still supported:

```sh
tools/run-cairo-proof.sh "$INPUT" "$OUT_DIR/tally"
```

For Linux memory diagnostics, wrap any command with `/usr/bin/time -v`.

### Split ProcessMessages Proofs

If the dense `process-messages` proof is killed by memory pressure, run the
split path first:

```sh
/usr/bin/time -v npm run prove:process-messages-split -- \
  --out-dir "$OUT_DIR/process-messages-split"
```

This proves:

```text
process-messages-boundary
process-message-coord-key
process-message-ecdh --message-index 0..4
process-message-signature --message-index 0..4
process-message-step-core --message-index 0..4
```

The deep split path lowers peak prover memory by moving the most expensive
BabyJubJub work out of the state-transition proof. The public outputs are
chainable: the boundary proof fixes the batch start/end hashes and state
commitments; `coord-key` binds `coordPubKeyHash` to `coordPrivKeyHash`; each
ECDH proof binds `coordPrivKeyHash + encPubKeyHash -> sharedKeyHash`; each
signature proof binds `pubKeyHash + R8Hash + packedCommandHash + S` to
`isSignatureValid`; and each core step exposes the same link hashes plus
`previous_message_hash`, `next_message_hash`, `current_state_root`, and
`new_state_root`. Production wrapper logic still needs to check all facts and
enforce that these public outputs form one consistent hash/root chain.

### Split ProcessDeactivate Proofs

If the dense `process-deactivate` proof is killed by memory pressure, run:

```sh
/usr/bin/time -v npm run prove:process-deactivate-split -- \
  --out-dir "$OUT_DIR/process-deactivate-split"
```

This proves:

```text
process-deactivate-boundary
process-deactivate-coord-key
process-deactivate-ecdh-command --message-index 0..4
process-deactivate-signature --message-index 0..4
process-deactivate-decrypt-current --message-index 0..4
process-deactivate-decrypt-new --message-index 0..4
process-deactivate-ecdh-leaf --message-index 0..4
process-deactivate-step-core --message-index 0..4
```

The deep split path moves the heavy BabyJubJub work out of the core root
transition. The core proof exposes link hashes for command ECDH, signature
verification, current/new ElGamal decrypt parity, deactivate-leaf ECDH, and
the same previous/next message hash plus active/deactivate root chain fields.
Production wrapper logic still needs to check all linked facts, enforce
hash/root chain continuity, enforce `deactivateIndex` increments by one, and
bind the first/last per-step deactivate commitments to the boundary output.

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

For `--all`, the root output directory also contains:

```text
all-proofs.json
```

which points to every per-circuit `proof-run.json`.

For `prove:all-split-small`, the root output directory contains:

```text
all-split-proofs.json
```

which points to the tally proof, add-new-key proof, ProcessMessages split
metadata, and ProcessDeactivate split metadata.

The final command inside the script is:

```sh
scarb verify --execution-id <execution-id>
```

A successful run must complete that verification step without error for every
circuit.

### Useful result checks

After a successful run:

```sh
cat "$OUT_DIR/all-proofs.json"
cat "$OUT_DIR/tally/proof-run.json"
cat "$OUT_DIR/add-new-key/proof-run.json"
cat "$OUT_DIR/process-messages/proof-run.json"
cat "$OUT_DIR/process-deactivate/proof-run.json"
```

The `publicOutput.felts` in each `*-prepared.json` is the canonical output that
the Starknet wrapper will eventually bind to an Integrity fact.

Check whether a tally proof run has enough metadata for the next Integrity
step:

```sh
npm run check:integrity -- \
  /absolute/path/to/tally/proof-run.json \
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
- Herodotus Integrity `proof_serializer` output for the Stone proof.

The expected intermediate result for the current local Scarb/Stwo proof path
is:

```text
Local scarb verification: yes
Local proof ready: yes
Local wrapper binding ready: yes
Integrity submission ready: no
```

To mark a proof run as Integrity-ready, rerun the checker only after producing
Stone/Integrity-compatible calldata:

```sh
npm run check:integrity -- \
  /absolute/path/to/tally/proof-run.json \
  --program-hash <tally_program_hash> \
  --proof-producer stone \
  --integrity-calldata /absolute/path/to/integrity-calldata.json \
  --text
```

Generate the JSON calldata wrapper from Herodotus Integrity's monolith
`proof_serializer` after you have a Stone proof JSON:

```sh
git clone https://github.com/HerodotusDev/integrity.git ~/integrity

npm run serialize:integrity-calldata -- \
  --stone-proof /absolute/path/to/stone-proof.json \
  --integrity-repo ~/integrity \
  --out /absolute/path/to/integrity-calldata.json \
  --text
```

If the serializer has already produced a raw calldata file, wrap it into the
same JSON shape with:

```sh
npm run serialize:integrity-calldata -- \
  --raw-calldata /absolute/path/to/raw-calldata \
  --out /absolute/path/to/integrity-calldata.json \
  --text
```

Do not pass the current `scarb prove` / Scarb-Stwo `proof.json` as
`--stone-proof`; Integrity verifies Stone prover proofs and the serializer
expects that proof format.

You can also export a self-contained handoff package for the next
Stone/Integrity integration step:

```sh
npm run export:integrity-handoff -- \
  /absolute/path/to/tally/proof-run.json \
  --program-hash <tally_program_hash> \
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

For the current Scarb/Stwo proof path, the handoff status should be
`local_proof_and_wrapper_binding_ready`. After a Stone/Integrity calldata
artifact exists, export again with:

```sh
npm run export:integrity-handoff -- \
  /absolute/path/to/tally/proof-run.json \
  --program-hash <real_tally_program_hash> \
  --proof-producer stone \
  --integrity-calldata /absolute/path/to/integrity-calldata.json \
  --out-dir /absolute/path/to/tally-integrity-handoff \
  --text
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
- `TallyVotes(2,1,1)` uses an existing AMACI operator fixture.
- `AddNewKey(2)`, `ProcessMessages(2,1,5)`, and
  `ProcessDeactivateMessages(2,5)` use synthetic fixtures that exercise the
  full migrated Cairo relation for those small parameters.
- Production-size `9-4-3-125` targets are not generated or proven by this
  flow.
- Real operator fixture cross-checking for non-tally circuits is still pending.
- It does not replace AMACI's internal non-PQ cryptography yet.
- It does not submit the proof to Integrity or Starknet.
- It uses the current local Scarb/Stwo proof flow. Stone/Integrity proof
  serialization remains a separate integration step.
- The stateful Cairo paths now short-circuit empty message slots at runtime, so
  empty slots skip ECDH/signature/decrypt/state-update work. The checked-in
  small synthetic `ProcessMessages` and `ProcessDeactivateMessages` fixtures
  currently use five non-empty messages, so this optimization affects sparse
  batches but does not reduce the dense five-message benchmark.
- Dense `ProcessMessages(2,1,5)` now has a deep split proof path. It is
  suitable for local prover feasibility checks, but Starknet wrapper support
  for verifying and chaining the boundary fact, coord-key fact, five ECDH
  facts, five signature facts, and five core-step facts is not yet
  implemented.
- Dense `ProcessDeactivateMessages(2,5)` now has a deep split proof path;
  wrapper support for checking the boundary fact, coord-key fact, command
  ECDH facts, signature facts, decrypt facts, leaf ECDH facts, and core-step
  facts is still pending.

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
