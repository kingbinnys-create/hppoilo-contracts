# Policy contract deterministic error mapping

This branch tracks the policy contract work for deterministic error code mapping and explicit policy violation handling.

## Scope
- Use the repo-wide shared error enum for stable numeric contract error codes.
- Ensure policy violations resolve to the most specific contract error rather than a generic denial.
- Keep policy denial reasons deterministic for agent UIs and transaction simulators.
- Verify the policy contract test suite covers the exact error paths.

## Verification
The contract is validated with:

```bash
cargo test -p astroid-policy --manifest-path contracts/modules/Cargo.toml
```

Current result in this environment: 86 passed, 0 failed.

Closes #317
