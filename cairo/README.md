# Cairo target

This folder is the first Cairo target for the AMACI `TallyVotes(2, 1, 1)` STARK
program. It is kept separate from the existing Circom circuits.

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
scarb execute --arguments-file /tmp/zkstark-amaci-cairo-args.json --print-program-output
npm --prefix .. run prove:tally
```

`tools/run-cairo-proof.sh` performs the full local flow:

1. prepare `scarb execute` arguments from an existing tally input JSON,
2. run `scarb prove --execute`,
3. run `scarb verify` against the generated proof.

For the current AMACI fixture, step 1 succeeds and produces the canonical
output, but step 2 is killed locally with exit code `137` / `Killed: 9`.

The latest local resource measurement for
`../amaci-operator/test-data/data/dora124w3vdmqtrjms9k4yhquqrd4r3qx5xww36ay5dg9wn8mnwe2e7dq5v8qfl/rust-inputgen/msg-tally/tally_inputs/000000.json`
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
