# Changelog — multisig

- Implement dynamic signature threshold adjustment: proposals for threshold updates are validated against current signer weight, timelocked, re-validated at execution time, and emit `threshold/changed` on success.

Notes:
- Tests for threshold proposals, execution, cancellation, and bounds are present in `src/test.rs`.

Closes #118
