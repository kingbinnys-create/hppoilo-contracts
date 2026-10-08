# Escrow time-lock and expiry checks

This branch tracks the issue for the Escrow contract time-lock and expiry validation work.

## Scope
- Enforce scheduled maturity before release on `Cliff` and `Linear` time-locked escrows.
- Require funds to be past the settlement deadline and grace window before refund / reclaim paths are allowed.
- Prevent premature or unauthorized withdrawals and refund attempts with deterministic `TimeLockActive`, `GraceActive`, or `EscrowExpired` errors.
- Verify ledger-time progression with escrow unit tests.

## Verification
The contract is validated with:

```bash
cargo test -p astroid-escrow --manifest-path contracts/modules/Cargo.toml
```

Current result in this environment: 67 passed, 0 failed.

Closes #338
