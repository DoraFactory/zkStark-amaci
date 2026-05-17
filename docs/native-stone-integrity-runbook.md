# Native Stone/Integrity Runbook

This is the current canonical path for producing Starknet/Integrity-compatible
proof artifacts from the optimized native AMACI tally circuit.

Do not use the removed legacy paths:

- `npm run prove:tally`
- `npm run prove:all-split-small`
- `npm run stone:air:tally-legacy`
- `--circuit tally`
- `tally_votes_stone`

Scarb/Stwo `prove:*native*` commands remain useful for local regression and
benchmark checks, but their `proof.json` files are not Stone proofs and must not
be passed to Integrity calldata serialization.

## 1. Set Output Directory

```sh
cd ~/zkStark-amaci
export STONE_OUT=/data/zkstark-amaci-proofs/stone-native-tally-$(date +%Y%m%d-%H%M%S)
mkdir -p "$STONE_OUT"
```

## 2. Generate Native Stone AIR

```sh
CAIRO_CORELIB_DIR=~/cairo-vm/cairo1-run/corelib \
/usr/bin/time -v npm run stone:air:tally -- \
  --out-dir "$STONE_OUT/stone-air" \
  2>&1 | tee "$STONE_OUT/stone-air.log"
```

Expected properties:

- circuit: `tally-native`
- executable: `tally_votes_native_stone`
- layout: `recursive_with_poseidon`
- output file: `$STONE_OUT/stone-air/stone-air-run.json`

## 3. Generate Integrity-Compatible Stone Proof

```sh
export STONE_PROOF_DIR="$STONE_OUT/stone-proof-integrity"

/usr/bin/time -v npm run stone:prove:tally -- \
  --air-run "$STONE_OUT/stone-air/stone-air-run.json" \
  --out-dir "$STONE_PROOF_DIR" \
  2>&1 | tee "$STONE_OUT/stone-proof-integrity.log"
```

Expected log lines:

```text
profile: integrity
channel_hash: poseidon3
commitment_hash: keccak256_masked160_lsb
pow_hash: keccak256
n_verifier_friendly_commitment_layers: 20
Verified proof successfully
Verifier annotations merged into: .../stone-proof.json
```

Do not pass an explicit `--parameter-file` for the normal Integrity path. The
generated params are adjusted to the AIR trace size and use the
Integrity-compatible Stone transcript/commitment profile.

## 4. Inspect Fact Hashes

```sh
npm run inspect:stone-fact -- \
  --stone-proof "$STONE_PROOF_DIR/stone-proof.json" \
  --out "$STONE_OUT/stone-fact.json" \
  --text | tee "$STONE_OUT/stone-fact.txt"
```

This records the program hash, output hash, fact hash, and public memory cell
counts that the AMACI wrapper will later need to bind to policy.

## 5. Serialize Integrity Split Calldata

```sh
npm run serialize:integrity-split-calldata -- \
  --stone-proof "$STONE_PROOF_DIR/stone-proof.json" \
  --calldata-generator ~/integrity-calldata-generator \
  --out-dir "$STONE_OUT/integrity-split" \
  --out "$STONE_OUT/integrity-split-calldata.json" \
  --layout recursive_with_poseidon \
  --hasher keccak_160_lsb \
  --stone-version stone6 \
  --memory-verification cairo1 \
  --text | tee "$STONE_OUT/integrity-split-calldata.txt"
```

Expected successful output:

```text
Serializer mode: swiftness-split
Layout: recursive_with_poseidon
Hasher: keccak_160_lsb
Stone version: stone6
Memory verification: cairo1
Verifier config hash: 0x...
```

The successful test run on 2026-05-17 produced:

```text
Calldata felts: 10804
Step files: 4
Verifier config hash: 0x7889bb7939fd1da7bd2d96376db9ca037dcee666914b8368d9221fb4e7feef0
```

## 6. Quick Artifact Check

```sh
find "$STONE_OUT/integrity-split/split-calldata" -maxdepth 1 -type f \
  -printf '%f %s bytes\n' | sort

node -e '
const fs = require("fs");
const j = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
console.log(JSON.stringify({
  calldataFelts: j.calldataFelts,
  stepCount: j.stepCount,
  verifierConfigHash: j.settings.verifierConfigHash,
}, null, 2));
' "$STONE_OUT/integrity-split-calldata.json"
```

## 7. Archive

```sh
tar -czf "$STONE_OUT.tar.gz" -C "$(dirname "$STONE_OUT")" "$(basename "$STONE_OUT")"
sha256sum "$STONE_OUT.tar.gz" | tee "$STONE_OUT.tar.gz.sha256"
du -sh "$STONE_OUT" "$STONE_OUT.tar.gz"
```

## Current Boundary

After step 5, the proof has been converted into Integrity split calldata, but it
has not yet been submitted onchain. The next stage is FactRegistry submission,
registered fact retrieval, and AMACI wrapper checks for the accepted fact hash,
program hash, public output, verifier config hash, and security assumptions.
