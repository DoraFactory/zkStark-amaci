# AddNewKey Compatibility Spec

This document describes the current Cairo compatibility target for AMACI
`AddNewKey(stateTreeDepth=2)`. The deactivate tree depth is fixed to
`stateTreeDepth + 2 = 4`.

## Public Fields

The executable binds these public values through canonical output:

- `deactivateRoot`
- `coordPubKeyHash = Poseidon(coordPubKey[0], coordPubKey[1])`
- `nullifier`
- `d1[2]`
- `d2[2]`
- `newPubKeyHash = Poseidon(newPubKey[0], newPubKey[1])`
- `pollId`
- `inputHash`

The input hash matches the Circom `AddNewKeyInputHasher` shape:

```text
inputHash = Sha256Hasher(9)(
  deactivateRoot,
  coordPubKeyHash,
  nullifier,
  d1[0],
  d1[1],
  d2[0],
  d2[1],
  newPubKeyHash,
  pollId
) mod BN254
```

## Relation

The Cairo executable enforces:

- `nullifier = Poseidon(oldPrivateKey, pollId)`
- `sharedKey = oldPrivateKey * coordPubKey`
- `sharedKeyHash = Poseidon(sharedKey[0], sharedKey[1])`
- `deactivateLeaf = Hasher5(c1[0], c1[1], c2[0], c2[1], sharedKeyHash)`
- `deactivateLeaf` is included in `deactivateRoot` at `deactivateIndex` with
  four quinary path levels
- `d1 = c1 + randomVal * BabyJubJub.Base8`
- `d2 = c2 + randomVal * coordPubKey`

BabyJubJub scalar multiplication is supplied as transcript witnesses and
verified inside Cairo using the same cross-multiplied Edwards addition
constraints used elsewhere in the migration.

## Current Limits

- Only `stateTreeDepth=2`, `deactivateTreeDepth=4` is implemented.
- The fixture tests are synthetic compatibility fixtures; real operator
  AddNewKey input cross-checks are still pending.
- This is still a compatibility migration of the current AMACI cryptography,
  not a post-quantum replacement for BabyJubJub/ElGamal.
