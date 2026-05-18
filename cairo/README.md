# Cairo Target

This package contains the Starknet-native AMACI proof circuits. The previous
Circom-compatible Cairo ports for BabyJubJub, BN254 Poseidon, and SHA-256 were
removed from this package; current executable targets use the native AMACI
field/public-output model and Starknet-friendly hashing.

## Native Executables

The current Scarb executable set is:

- `tally_votes_native`
- `tally_votes_native_stone`
- `add_new_key_native`
- `process_messages_native_boundary`
- `process_message_coord_key_native`
- `process_message_ecdh_native`
- `process_message_decrypt_native`
- `process_message_signature_native`
- `process_message_step_core_native`
- `process_deactivate_native_boundary`
- `process_deactivate_coord_key_native`
- `process_deactivate_ecdh_native`
- `process_deactivate_signature_native`
- `process_deactivate_decrypt_native`
- `process_deactivate_step_core_native`

All executable modules are declared through `src/lib.cairo` as `native_*`
modules only.

## Local Validation

Build the native Cairo package:

```sh
scarb build
```

Run the Cairo test target:

```sh
scarb test
```

From the repository root, the higher-level validation commands are:

```sh
npm test
npm run test:cairo
npm run test:contracts
```

`npm run test:cairo-execute` runs generated fixture execution tests for the
native executable set. It is intentionally limited to native targets.

## Proving Flows

The local Scarb/Stwo helper accepts native circuits only:

```sh
npm run prove:tally-native -- --out-dir /tmp/amaci-tally-native
npm run prove:all-native-split-small -- --out-dir /tmp/amaci-all-native-split
```

The Stone helpers are also wired around native circuits:

```sh
npm run stone:air:tally -- --out-dir /tmp/amaci-stone-tally/stone-air
npm run stone:prove:tally -- \
  --air-run /tmp/amaci-stone-tally/stone-air/stone-air-run.json \
  --out-dir /tmp/amaci-stone-tally/stone-proof
npm run stone:prove:all-native-split-small -- \
  --out-dir /tmp/amaci-all-native-stone-split
```

Atlantic submissions are generated from the native Cairo1 program/input files,
not from the removed legacy executable targets.

## Compatibility Layer

Some JavaScript fixture builders and regression tests still keep legacy AMACI
compatibility evaluators so old sample data can be transformed into native
public inputs and compared against historical behavior. Those helpers are not
Scarb executable targets and are not used as Starknet/Cairo crypto
implementations.
