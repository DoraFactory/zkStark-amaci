# Stark Native AMACI Optimization Notes

Last updated: 2026-05-16

## Current Direction

The current Stark-native AMACI path is no longer trying to preserve every
Circom-era cryptographic primitive. The goal is to keep the AMACI state
transition meaningful while making the circuit/proof shape fit Starknet and
Stone/STARK execution better.

The native path therefore replaces the heavy migrated compatibility model with:

- Starknet-native `felt252` public commitments.
- Starknet-native Poseidon for native commitments and input hashes.
- Smaller proof-mode entrypoints built specifically for Stone.
- Split local circuits for process-message and process-deactivate flows.

The compatibility path is still present for comparison, but new Stone work
should target the native optimized path.

## Implemented Optimization Work

### Native Tally Circuit

Native tally is implemented in:

- `cairo/src/native_tally_votes.cairo`
- `src/tally/native-tally-votes.mjs`
- `src/native-cairo-input.mjs`
- `tools/prepare-native-tally-input.mjs`

Main changes:

- Replaced BN254 Poseidon/SHA-style public hash claims with Starknet Poseidon
  commitments over `felt252`.
- Reduced the tally executable arguments from the legacy witness-heavy shape to
  a fixed native input shape.
- Public output is now a compact native AMACI v2 output with:
  - magic/version/circuit id/hash scheme
  - tree-depth metadata
  - packed values
  - state commitment
  - current/new tally commitments
  - native input hash

### Stone Native Tally Entrypoint

Stone proof mode needs a single `Array<felt252>` input and a single
`Array<felt252>` output. The native Stone wrapper is:

- `cairo/src/stone_native_tally_votes.cairo`
- executable target: `tally_votes_native_stone`

The default Stone command now points to the native path:

```sh
npm run stone:air:tally
```

This is an alias for:

```sh
tools/run-stone-air.sh --circuit tally-native --input fixtures/tally-small/000000.json
```

The old compatibility path is still available explicitly:

```sh
npm run stone:air:tally-legacy
```

### Stone AIR/Proof Tooling

Updated tooling:

- `tools/run-stone-air.sh`
- `tools/run-stone-proof.sh`
- `tools/generate-stone-params.mjs`

Important behavior:

- `stone:air:tally` now builds a minimal native Stone package instead of the
  full Cairo package.
- Native tally uses `recursive_with_poseidon`, because it uses the Poseidon
  builtin.
- The generated AIR metadata records:
  - `circuit: tally-native`
  - `stoneExecutable: tally_votes_native_stone`
  - `layout: recursive_with_poseidon`
- Stone params are generated from the AIR trace size so FRI degree matches the
  actual `n_steps`.

### Fixed-Arity Poseidon Optimization

The initial native Stone run failed inside `cairo1-run --proof_mode` with:

```text
Error: VirtualMachine(Unexpected)
```

The failing Sierra still contained `core::poseidon::_poseidon_hash_span_inner`
and `BuiltinCosts`. The native tally hashes were changed from
`poseidon_hash_span(...)` to fixed-arity `PoseidonTrait` updates:

```cairo
let mut state = PoseidonTrait::new();
state = state.update(left);
state = state.update(right);
state.finalize()
```

After this change, the Stone runner Sierra no longer contains
`poseidon_hash_span_inner` or `BuiltinCosts`, and `cairo1-run --proof_mode`
succeeds.

Relevant commits:

- `90e2aee Use native tally for Stone AIR path`
- `92de69f Use fixed arity Poseidon in native tally`

## Measured Results

### Legacy Stone Tally Baseline

This was the old compatibility Stone path:

- circuit: `tally`
- executable: `tally_votes_stone`
- layout: `recursive`
- Cairo args: `488` felts
- AIR `n_steps`: `67,108,864`
- STARK degree bound: `2^30`
- AIR max RSS: `10,461,672 KB`
- Stone proving result: OOM killed
- OOM proof max RSS before kill: about `64,291,364 KB`

The legacy proof could generate AIR, but the Stone prover could not finish on a
64 GiB machine.

### Native Stone Tally Result

Successful run:

```text
/data/zkstark-amaci-proofs/stone-native-tally-20260516-144921
```

AIR command:

```sh
CAIRO_CORELIB_DIR=~/cairo-vm/cairo1-run/corelib \
/usr/bin/time -v npm run stone:air:tally -- \
  --out-dir "$STONE_OUT/stone-air"
```

AIR result:

- circuit: `tally-native`
- executable: `tally_votes_native_stone`
- layout: `recursive_with_poseidon`
- Cairo args: `95` felts
- AIR max RSS: `689,296 KB`
- wall time: `1.88s`
- status: success

Stone proof command:

```sh
/usr/bin/time -v npm run stone:prove:tally -- \
  --air-run "$STONE_OUT/stone-air/stone-air-run.json" \
  --out-dir "$STONE_OUT/stone-proof"
```

Stone proof result:

- AIR `n_steps`: `131,072`
- STARK degree bound: `2^21`
- generated `fri_step_list`: `[0, 4, 4, 4, 3]`
- max RSS: `6,209,736 KB`
- wall time: `19.96s`
- local verifier: `Verified proof successfully`
- exit status: `0`

### Reduction Summary

| Metric | Legacy Stone tally | Native Stone tally | Change |
| --- | ---: | ---: | ---: |
| Cairo input felts | 488 | 95 | 5.1x smaller |
| AIR `n_steps` | 67,108,864 | 131,072 | 512x smaller |
| STARK degree bound | 2^30 | 2^21 | 512x smaller |
| AIR max RSS | 10,461,672 KB | 689,296 KB | about 15.2x lower |
| Prover max RSS | OOM at about 64,291,364 KB | 6,209,736 KB | about 10.4x lower than OOM point |
| Prover result | killed / exit 137 | verified / exit 0 | unblocked |

The key result is that native tally Stone proving moved from "cannot complete on
64 GiB RAM" to "locally proved and verified in about 20 seconds".

## Relation To Local Scarb/Stwo Proofs

The native Scarb/Stwo split path is still useful for local development and
regression testing:

```sh
npm run prove:all-native-split-small -- \
  --tally-input fixtures/tally-small/000000.json \
  --out-dir "$OUT/all-native-split"
```

A previous native split run completed with:

- proof runs: `56`
- local verification logs: `56`
- wall time: `9:29.50`
- max RSS: `18,574,716 KB`

However, Scarb/Stwo proof JSON is not the same artifact as a Stone proof ready
for Integrity/Starknet. For Starknet application-level verification, the current
practical path remains Stone plus Integrity-compatible serialization.

## Does This Mean The Proof Can Be Verified On Starknet?

Short answer: not yet, but it is now much closer.

What we have now:

- A real Stone proof for native tally.
- Local `cpu_air_verifier` verification succeeds.
- The proof uses `recursive_with_poseidon`, which is a layout supported by
  Starknet/Integrity split serialization flows.

What this does not prove yet:

- It does not mean the proof has already been serialized into Starknet calldata.
- It does not mean Integrity's FactRegistry has accepted and registered the
  proof on Starknet.
- It does not mean an AMACI wrapper contract has checked the registered fact,
  program hash, public output, state transition, and security bits.

According to the current Integrity/Stone flow:

- Integrity is the Starknet-side STARK verifier for Stone proofs.
- A Stone proof must be serialized into calldata accepted by Integrity.
- For Starknet serialization, monolith mode supports only `recursive`; split
  mode supports `recursive_with_poseidon`.
- Integrity registers a fact after verification; downstream contracts should
  check the fact hash, security bits, and verifier settings.

So for our native tally proof, the next required step is split Integrity
serialization and onchain FactRegistry submission, not another local Stone
verification.

## Next Steps

1. Archive the successful proof run.

```sh
export OUT=/data/zkstark-amaci-proofs/stone-native-tally-20260516-144921
tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")"
sha256sum "$OUT.tar.gz" | tee "$OUT.tar.gz.sha256"
du -sh "$OUT" "$OUT.tar.gz"
```

2. Generate Integrity/Starknet calldata for the native Stone proof.

Because the layout is `recursive_with_poseidon`, use the split serialization
path rather than monolith serialization.

3. Submit split verifier transactions to Starknet Integrity/FactRegistry.

The submitted settings must match the proof:

- layout: `recursive_with_poseidon`
- Stone version: must match the prover/serializer
- memory verification mode: must match the selected Integrity verifier
- hasher/verifier configuration: must match the serializer output

4. Record the registered fact.

Capture:

- `fact_hash`
- `verification_hash`
- `security_bits`
- verifier settings/config hash
- transaction hashes

5. Wire AMACI wrapper verification.

The AMACI contract should not trust "a proof was verified" generically. It
should check that the registered fact binds to the expected program hash and
native public output, and then apply the expected AMACI state transition.

## References

- Herodotus Integrity docs:
  https://docs.herodotus.dev/herodotus-docs/scaling-solutions/integrity-verifier
- Integrity repository:
  https://github.com/HerodotusDev/integrity
- Stone CLI Starknet serialization notes:
  https://github.com/zksecurity/stone-cli
