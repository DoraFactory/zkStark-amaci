# zkStark-amaci

Parallel Stark/STARK proof-layer prototype for AMACI.

This directory is intentionally independent from the existing Circom,
CosmWasm, SDK, and operator code. The first milestone targets only the
`TallyVotes` relation for the small parameter set:

- `stateTreeDepth = 2`
- `intStateTreeDepth = 1`
- `voteOptionTreeDepth = 1`

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

- `spec/tally-votes-compat.md` documents the compatibility contract.
- `src/` contains a deterministic JavaScript reference implementation for the
  `TallyVotes` relation and public-output encoding.
- `src/compat/poseidon-bn254.mjs` contains a pure JavaScript implementation of
  the same BN254 Poseidon permutation used by the existing Circom package. It
  is used to generate and verify the Cairo Poseidon constants and test vectors.
- `tools/prepare-tally-input.mjs` validates an existing tally input JSON and
  emits canonical public output, fixed-size Cairo program input, plus optional
  Integrity fact hashes when a program hash is supplied.
- `tests/` exercises valid and invalid tally inputs against existing AMACI
  operator fixtures with 10-field state leaves.
- `cairo/` contains the first fixed-size `TallyVotes(2, 1, 1)` Cairo relation
  migration. It computes AMACI `Hasher10`, Circom-compatible BN254 Poseidon
  T3/T6, quinary tree hashes, and the SHA-256 `inputHash` inside Cairo, while
  retaining hash claims only as witness compatibility assertions against the
  generated input.
- `contracts/` contains the Starknet target scaffolding for the Integrity
  wrapper.

## Current proof status

The local Cairo execution flow succeeds for the existing AMACI fixture:

```text
../amaci-operator/test-data/data/dora124w3vdmqtrjms9k4yhquqrd4r3qx5xww36ay5dg9wn8mnwe2e7dq5v8qfl/rust-inputgen/msg-tally/tally_inputs/000000.json
```

Execute locally with:

```sh
npm run prepare:cairo-args
cd cairo
scarb execute --arguments-file /tmp/zkstark-amaci-cairo-args.json --print-program-output
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

## Generating a proof on a high-performance machine

This is the current end-to-end local proof validation path for the migrated
AMACI `TallyVotes(2, 1, 1)` Cairo program. It does not submit anything to
Starknet or Integrity yet. Success means:

1. the existing AMACI tally input is converted into canonical Cairo arguments,
2. `scarb prove --execute` generates a local STARK proof for the Cairo program,
3. `scarb verify` verifies the generated proof locally.

### Machine requirements

Use Linux/amd64 for the first full proof run. The current macOS/arm64 machine
can compile, test, and execute the program, but proof generation is killed by
the OS before completion.

Recommended starting point:

- Ubuntu 22.04 or 24.04 on amd64
- 16 or more CPU cores
- 64 GB RAM minimum, 128 GB RAM preferred for the first proof attempt
- fast local SSD/NVMe storage
- Node.js 20 or newer
- Scarb/Cairo toolchain compatible with `cairo/Scarb.toml`
  (`edition = "2024_07"`, Cairo/Scarb `2.18.0` in the current lockfile)
- `scarb execute`, `scarb prove`, and `scarb verify` available in the installed
  toolchain

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

### Input fixture

The proof script accepts any compatible AMACI `TallyVotes(2, 1, 1)` input JSON.
The fixture used during this migration is:

```text
amaci-operator/test-data/data/dora124w3vdmqtrjms9k4yhquqrd4r3qx5xww36ay5dg9wn8mnwe2e7dq5v8qfl/rust-inputgen/msg-tally/tally_inputs/000000.json
```

If the high-performance machine has the full parent repository layout, run from
`maci/zkStark-amaci` and use the npm shortcut:

```sh
npm run prove:tally
```

If the machine only has this standalone repository, copy the input JSON to the
machine and pass its absolute path:

```sh
git clone https://github.com/DoraFactory/zkStark-amaci.git
cd zkStark-amaci

INPUT=/absolute/path/to/000000.json
OUT_DIR=/absolute/path/to/proof-output

tools/run-cairo-proof.sh "$INPUT" "$OUT_DIR"
```

### Preflight checks

Run these before the expensive proof attempt:

```sh
npm test

cd cairo
scarb check
scarb test
scarb fmt --check
cd ..

node tools/prepare-tally-input.mjs \
  "$INPUT" \
  --out "$OUT_DIR/tally-prepared.json" \
  --cairo-input-out "$OUT_DIR/tally-cairo-input.json" \
  --cairo-args-out "$OUT_DIR/tally-cairo-args.json"

cd cairo
scarb execute \
  --arguments-file "$OUT_DIR/tally-cairo-args.json" \
  --print-program-output \
  --print-resource-usage
cd ..
```

Expected execution characteristics for the current fixture:

- execution steps: `19,514,414`
- max memory address: `27,947,371`
- memory holes: `5,287,008`
- range-check builtin uses: `5,139,640`
- bitwise builtin uses: `2,880`
- output builtin uses: `16`

If `scarb execute` fails, do not run the prover. Fix the input, toolchain, or
Cairo build first.

### Proof command

Run the full local proof flow:

```sh
INPUT=/absolute/path/to/000000.json
OUT_DIR=/absolute/path/to/proof-output

tools/run-cairo-proof.sh "$INPUT" "$OUT_DIR"
```

For memory diagnostics on Linux, this wrapper is useful:

```sh
/usr/bin/time -v tools/run-cairo-proof.sh "$INPUT" "$OUT_DIR"
```

The script writes:

- `$OUT_DIR/tally-prepared.json`: parsed public fields, derived values, and
  canonical public output
- `$OUT_DIR/tally-cairo-input.json`: structured Cairo input
- `$OUT_DIR/tally-cairo-args.json`: `scarb execute/prove` argument file
- `$OUT_DIR/proof-run.json`: generated execution id and proof file path
- `cairo/target/execute/zkstark_amaci_tally/execution<id>/proof/proof.json`:
  generated local proof

The final command inside the script is:

```sh
scarb verify --execution-id <execution-id>
```

A successful run must complete that verification step without error and write
`proof-run.json`.

### Useful result checks

After a successful run:

```sh
cat "$OUT_DIR/proof-run.json"
node tools/prepare-tally-input.mjs "$INPUT" --out "$OUT_DIR/recheck.json"
```

The `publicOutput.felts` in `tally-prepared.json` is the canonical output that
the Starknet wrapper will eventually bind to an Integrity fact. The current
encoding is fixed as:

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

- This validates the Cairo/STARK migration of AMACI `TallyVotes(2, 1, 1)` only.
- It does not prove `ProcessMessages`.
- It does not replace AMACI's internal non-PQ cryptography yet.
- It does not submit the proof to Integrity or Starknet.
- It uses the current local Scarb/Stwo proof flow. Stone/Integrity proof
  serialization remains a separate integration step.

## Commands

From this directory:

```sh
npm test
node tools/prepare-tally-input.mjs \
  ../amaci-operator/test-data/data/dora124w3vdmqtrjms9k4yhquqrd4r3qx5xww36ay5dg9wn8mnwe2e7dq5v8qfl/rust-inputgen/msg-tally/tally_inputs/000000.json
node tools/prepare-tally-input.mjs \
  ../amaci-operator/test-data/data/dora124w3vdmqtrjms9k4yhquqrd4r3qx5xww36ay5dg9wn8mnwe2e7dq5v8qfl/rust-inputgen/msg-tally/tally_inputs/000000.json \
  --cairo-input-out /tmp/zkstark-amaci-cairo-input.json
node tools/export-hash-vectors.mjs \
  ../amaci-operator/test-data/data/dora124w3vdmqtrjms9k4yhquqrd4r3qx5xww36ay5dg9wn8mnwe2e7dq5v8qfl/rust-inputgen/msg-tally/tally_inputs/000000.json \
  --out /tmp/zkstark-amaci-hash-vectors.json
node tools/verify-hash-vectors.mjs /tmp/zkstark-amaci-hash-vectors.json
```

With a compiled Cairo child program hash:

```sh
node tools/prepare-tally-input.mjs \
  ../amaci-operator/test-data/data/dora124w3vdmqtrjms9k4yhquqrd4r3qx5xww36ay5dg9wn8mnwe2e7dq5v8qfl/rust-inputgen/msg-tally/tally_inputs/000000.json \
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
