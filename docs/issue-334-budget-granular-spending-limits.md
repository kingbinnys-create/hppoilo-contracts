# Budget granular spending limit checks

This branch tracks the budget contract work for issue #334.

## Scope
- Refine budget consumption tracking for periodic spending allocations.
- Correctly evaluate the current window for daily or monthly limits.
- Keep spent totals and remaining balances aligned across window boundaries.
- Reject transactions that exceed the remaining allowance within the active period.
- Emit structured Soroban events when the budget is exhausted.
- Verify rollover and reset behaviors with budget unit tests.

## Verification

The contract is validated with:

```bash
cargo test -p astroid-budget --manifest-path contracts/modules/Cargo.toml
```

Current result in this environment: 77 passed, 0 failed.

Closes #334
