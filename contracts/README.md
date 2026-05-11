# Starknet wrapper target

This folder contains the minimal Starknet wrapper boundary for the
AMACI `TallyVotes` STARK proof path.

The wrapper is intentionally small:

- keep current tally state,
- rebuild the canonical public output from current state and submitted
  `new_tally_commitment`,
- calculate the Integrity fact hash for the fixed Cairo child program,
- require enough security bits in Integrity,
- update the tally commitment only after the fact is valid.

`MockIntegrity` is included for local devnet and wrapper smoke tests. It
implements the same minimal `IIntegrity` method used by the wrapper and lets a
test script assign security bits to a `fact_hash` before calling
`submit_tally_fact`.

The exact Integrity dependency version should be pinned when the Starknet
toolchain is installed and the contract is compiled.

Current status:

- `scarb check` passes.
- `scarb test` is routed through `snforge test`.
- unit tests cover the canonical public-output hash and fact-hash binding
  against `starknet.js` vectors.
- integration tests deploy `MockIntegrity` plus `TallyVotesStarkWrapper`, set
  fact security bits, call `submit_tally_fact`, and assert the wrapper state
  update. They also cover bootloaded fact mode and negative cases for
  unregistered facts, insufficient security bits, fact/public-output mismatch,
  and stale replay after the tally commitment has changed.
- the wrapper supports plain child-program fact hashes and bootloaded fact
  hashes; pass `bootloader_program_hash = 0` for plain mode, or a nonzero
  bootloader hash for the Scarb/bootloader output shape.
- `MockIntegrity` compiles as a local substitute for FactRegistry while the
  real Integrity interface is not pinned.
